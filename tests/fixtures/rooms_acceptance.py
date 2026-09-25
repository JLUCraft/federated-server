"""Run disposable two-school federation acceptance using real school HTTP services and Paper.

Run after building the federated-server workspace.
Assets are pinned and pre-fetched; secrets/results stay in ROOMS_ACCEPTANCE_STATE outside Git.
"""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid

BASE = Path(__file__).resolve().parents[3]
CORE = BASE / 'federated-server/target/debug'
SERVER = BASE / 'federated-server/target/debug/federated-server'
ASSETS = Path(os.environ['ROOMS_ACCEPTANCE_STATE']).resolve()
PINNED_ASSETS = {
    'paper-1.20.4-496.jar': '9c6419c3504db84d437d4bbeb5b9d27d548a009a3ed2f1c617b62e7341cfeee3',
    'mojang_1.20.4.jar': 'c03fa6f39daa69ddf413c965a3a83084db746a7a138ce535a693293b5472d363',
}
for filename, expected in PINNED_ASSETS.items():
    with (ASSETS / filename).open('rb') as asset:
        if hashlib.file_digest(asset, 'sha256').hexdigest() != expected:
            raise ValueError('Pinned asset hash mismatch: ' + filename)
os.umask(0o077)
STATE = Path(tempfile.mkdtemp(prefix='attempt-', dir=ASSETS))
processes = []
logs = []


def run(args, **kwargs):
    return subprocess.check_output([str(a) for a in args], text=True, timeout=60, **kwargs).strip()


def spawn(args, name, **kwargs):
    log = (STATE / (name + '.log')).open('w')
    logs.append(log)
    process = subprocess.Popen([str(a) for a in args], stdout=log, stderr=subprocess.STDOUT,
                               start_new_session=True, **kwargs)
    processes.append(process)
    return process


def until(check, seconds=150, process=None):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            raise RuntimeError('fixture process exited: ' + str(process.returncode))
        result = check()
        if result:
            return result
        time.sleep(0.25)
    raise TimeoutError('acceptance condition timed out')


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def ready(address):
    try:
        with socket.create_connection(address, timeout=0.2):
            return True
    except OSError:
        return False


def stop(process):
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGINT)
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


try:
    env = os.environ | {'ROOMS_ACCEPTANCE_STATE': str(STATE), 'UNIONCTL': str(CORE / 'unionctl'),
                       'NODE_OPTIONS': '--max-old-space-size=512'}
    schools_process = spawn([BASE / 'federated-skinstation/node_modules/.bin/tsx',
                              BASE / 'federated-skinstation/test/fixtures/rooms-schools.ts'], 'schools', env=env)
    until(lambda: (STATE / 'schools.json').exists(), process=schools_process)
    schools = json.loads((STATE / 'schools.json').read_text())
    stop(schools_process)
    founders = [json.loads(run([CORE / 'unionctl', 'trust', 'founder', '--member', school['school'] + '-chair',
        '--club', school['school'], '--peer', school['identities']['root']])) for school in schools]
    genesis = STATE / 'identity-genesis.json'
    genesis.write_text(json.dumps({'federation': 'rooms-acceptance', 'founders': founders, 'quorum': 2}))
    identity_pin = run([CORE / 'unionctl', 'trust', 'digest', '--genesis', genesis])
    relay_peer = run([CORE / 'unionctl', 'keygen', '--out', STATE / 'relay.key'])
    relay_port = port()
    relay_base = f'/ip4/127.0.0.1/tcp/{relay_port}'
    relay_address = relay_base + '/p2p/' + relay_peer
    relay_config = STATE / 'relay.json'
    relay_config.write_text(json.dumps({'node': {'key': str(STATE / 'relay.key'),
        'listen': [relay_base], 'external': [relay_base]},
        'services': {'directory': True, 'relay': True, 'identity': {'genesis': str(genesis), 'genesis_hash': identity_pin, 'log': str(STATE / 'identity.jsonl'), 'writer': True, 'max_staleness_seconds': 60}}}))
    relay = spawn([SERVER, 'run', '--config', relay_config], 'relay')
    until(lambda: ready(('127.0.0.1', relay_port)), process=relay)
    cache_args = ['--genesis', genesis, '--genesis-hash', identity_pin, '--log', STATE / 'cli-cache.jsonl']
    sequence = 0
    def append(action, keys):
        global sequence
        sequence += 1
        target = ['--key', keys[0], '--address', relay_address, '--peer', relay_peer]
        run([CORE / 'unionctl', 'trust', 'sync', *cache_args, *target])
        action_path = STATE / f'action-{sequence}.json'
        action_path.write_text(json.dumps(action))
        record = STATE / f'draft-{sequence}.json'
        run([CORE / 'unionctl', 'trust', 'draft', *cache_args, '--action', action_path, '--out', record])
        for index, key in enumerate(keys):
            signed = STATE / f'signed-{sequence}-{index}.json'
            run([CORE / 'unionctl', 'trust', 'sign', '--key', key, '--record', record, '--out', signed])
            record = signed
        run([CORE / 'unionctl', 'trust', 'submit', *cache_args, *target, '--record', record])
    for school in schools:
        path = Path(school['path'])
        member = school['school'] + '-member'
        append({'type': 'confirm_member', 'member': member, 'club': school['school'], 'device': school['identities']['host'],
            'evidence': 'manual_verification', 'verifier': None}, [path / 'root.key', path / 'host.key'])
        append({'type': 'bind_device', 'member': member, 'device': school['identities']['player']}, [path / 'host.key', path / 'player.key'])
        append({'type': 'bind_game_profile', 'member': member, 'club': school['school'], 'profile': school['profile']['id']}, [path / 'root.key', path / 'host.key'])
    print('Both skin stations stopped; chairs confirmed members in the unified identity log.', flush=True)
    hosts = []
    for index, school in enumerate(schools):
        path = Path(school['path'])
        game = path / 'minecraft'
        game.mkdir()
        (game / 'cache').mkdir()
        shutil.copyfile(ASSETS / 'mojang_1.20.4.jar', game / 'cache/mojang_1.20.4.jar')
        backend = port()
        (game / 'eula.txt').write_text('eula=true\n')
        (game / 'server.properties').write_text(
            f'server-ip=127.0.0.1\nserver-port={backend}\nonline-mode=false\nenforce-secure-profile=false\n'
            'level-type=minecraft:flat\nview-distance=2\nsimulation-distance=2\nmax-players=4\n'
            'spawn-protection=0\nspawn-npcs=false\nspawn-animals=false\nspawn-monsters=false\n'
            'generate-structures=false\nallow-nether=false\n')
        (game / 'bukkit.yml').write_text('settings:\n  allow-end: false\n')
        forwarding = uuid.uuid4().hex + uuid.uuid4().hex
        secret = path / 'forwarding.key'
        secret.write_text(forwarding)
        (game / 'config').mkdir()
        (game / 'config/paper-global.yml').write_text('proxies:\n  velocity:\n    enabled: true\n    online-mode: false\n    secret: "' + forwarding + '"\n')
        service = str(uuid.uuid4())
        java = '/usr/lib/jvm/java-21-openjdk-amd64/bin/java'
        command = f'{java} -Xms256M -Xmx768M -XX:ActiveProcessorCount=1 -jar {ASSETS / "paper-1.20.4-496.jar"} --nogui'
        command = 'sh -c ' + shlex.quote('exec ' + command + ' > console.log 2>&1')
        config = {'service': service, 'name': school['school'] + ' room', 'forwarding_secret': str(secret),
                  'instance': {'id': school['school'], 'directory': str(game), 'backend': f'127.0.0.1:{backend}',
                               'server': {'nickname': school['school'], 'start_command': command, 'stop_command': 'stop', 'server_type': 'minecraft/java',
                                          'input_encoding': 'utf-8', 'output_encoding': 'utf-8', 'auto_restart': False, 'auto_restart_max_times': 0,
                                          'rcon': None, 'java_path': '', 'isolated_tmpdir': False, 'jvm_properties': []}},
                  'club': school['school'], 'join_clubs': [entry['school'] for entry in schools]}
        config_path = path / 'room.json'
        config_path.write_text(json.dumps({'node': {'key': str(path / 'host.key'), 'listen': ['/ip4/127.0.0.1/tcp/0'],
            'bootstrap': [relay_address], 'reserve': [relay_address]}, 'services': {
            'identity': {'genesis': str(genesis), 'genesis_hash': identity_pin, 'log': str(path / 'identity.jsonl'),
                'writer': False, 'source': {'address': relay_address, 'peer': relay_peer}, 'max_staleness_seconds': 60},
            'member_rooms': [config]}}))
        host = spawn([SERVER, 'run', '--config', config_path], 'host-' + str(index))
        until(lambda: '"room:' in (STATE / ('host-' + str(index) + '.log')).read_text(), process=host)
        hosts.append({'process': host, 'service': service, 'peer': school['identities']['host']})
        print(school['school'] + ': real Paper room published', flush=True)
    # A separate discovery client must find both hosts via the seed/provider index.
    discover_key = STATE / 'discovery.key'
    run([CORE / 'unionctl', 'keygen', '--out', discover_key])
    discovered = json.loads(run([CORE / 'unionctl', 'rooms', '--key', discover_key, '--bootstrap', relay_address]))
    if {room['service'] for room in discovered['rooms']} != {host['service'] for host in hosts}:
        raise AssertionError('cross-school room discovery incomplete')
    spec = importlib.util.spec_from_file_location('minecraft_login', Path(__file__).with_name('minecraft_login.py'))
    minecraft = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(minecraft)
    result = []
    for index, school in enumerate(schools):
        other = hosts[1 - index]
        path = Path(school['path'])
        proxy_port = port()
        # Only the circuit route is supplied: this verifies relay fallback, not LAN direct dialing.
        circuit = relay_address + '/p2p-circuit/p2p/' + other['peer']
        proxy = spawn([CORE / 'unionctl', 'proxy', '--key', path / 'player.key', '--peer', other['peer'],
                       '--address', circuit, '--service', other['service'],
                       '--bind', f'127.0.0.1:{proxy_port}'], 'proxy-' + str(index))
        until(lambda: 'local game proxy ready' in (STATE / ('proxy-' + str(index) + '.log')).read_text(), process=proxy)
        joined = minecraft.login(('127.0.0.1', proxy_port), school['profile'])
        if joined['profile'] != school['profile']['id']:
            raise AssertionError('authenticated Minecraft UUID changed')
        result.append({'school': school['school'], 'destination': schools[1-index]['school'], **joined})
        print(school['school'] + ' joined the other school through relay: ' + joined['phase'], flush=True)
        stop(proxy)
    (STATE / 'result.json').write_text(json.dumps({'skin_stations_running': False, 'identity_source': 'append_only_manual_chair_signature', 'discovery': discovered, 'joins': result}, indent=2))
    print('Acceptance artifacts: ' + str(STATE), flush=True)
finally:
    for process in reversed(processes):
        stop(process)
    for log in logs:
        log.close()
