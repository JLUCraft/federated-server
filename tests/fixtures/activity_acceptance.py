"""Single-host, real-Paper activity and crash/restart acceptance without AI providers.

Build the acceptance driver first. Paper and the scoring plugin must already exist in
the workspace's build directories. Private fixture state stays under the supplied state root.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shlex
import signal
import socket
import struct
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid

from minecraft_activity import ActivityClient, BLOCK_Y, PLATFORM_Y

BASE = Path(__file__).resolve().parents[3]
TARGET = BASE / 'federated-server/target'
DRIVER = TARGET / 'debug/examples/acceptance-driver'
PAPER = TARGET / 'paper-26.3-209.jar'
PLUGIN = BASE / 'paper-scoring-template/build/libs/union-paper-scoring-0.1.0.jar'
JAVA = Path('/usr/lib/jvm/java-25-openjdk-amd64/bin/java')
PAPER_SHA256 = '0a056c7648cfa0ca8d9b8c833a2bd2e1313ed4f1393a5125dd3444a4ee257e22'
SLICE_MS = 300_000
SOURCE = 'activity-live'
CLUB = 'acceptance'
LOG_PREFIX = 'activity-live-20261022'


def run(args, **kwargs):
    result = subprocess.run([str(a) for a in args], text=True, capture_output=True,
                            timeout=60, **kwargs)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    return result.stdout.strip()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def port():
    with socket.socket() as connection:
        connection.bind(('127.0.0.1', 0))
        return connection.getsockname()[1]


class Rcon:
    def __init__(self, address, password):
        self.socket = socket.create_connection(address, timeout=10)
        self.request = 0
        self.send(3, password)
        while True:
            response, kind, _ = self.receive()
            if kind == 2:
                if response != self.request:
                    raise RuntimeError('Fixture RCON authentication failed')
                break

    def exact(self, size):
        data = b''
        while len(data) < size:
            chunk = self.socket.recv(size - len(data))
            if not chunk:
                raise EOFError('RCON closed')
            data += chunk
        return data

    def send(self, kind, body):
        self.request += 1
        data = struct.pack('<ii', self.request, kind) + body.encode() + b'\0\0'
        self.socket.sendall(struct.pack('<i', len(data)) + data)

    def receive(self):
        size, = struct.unpack('<i', self.exact(4))
        if not 10 <= size <= 1024 * 1024:
            raise ValueError('Invalid RCON response size')
        data = self.exact(size)
        request, kind = struct.unpack('<ii', data[:8])
        return request, kind, data[8:-2].decode()

    def command(self, command):
        self.send(2, command)
        request, _, response = self.receive()
        if request != self.request:
            raise ValueError('Unexpected RCON response id')
        return response

    def close(self):
        self.socket.close()


class Acceptance:
    def __init__(self, state):
        self.state = state
        self.host = None
        self.proxies = []
        self.clients = []
        self.handles = []
        self.sequence = time.time_ns()
        self.generation = max((int(path.stem.rsplit('-', 1)[1])
                               for path in TARGET.glob(LOG_PREFIX + '-host-*.log')), default=0)
        self.rcon = None
        self.paper_group = None
        self.result = {'validation_channel': 'local', 'ai_services': 'frozen',
                       'checks': [], 'passed': False, 'private_state': str(state)}
        previous = TARGET / (LOG_PREFIX + '-result.json')
        if previous.exists():
            saved = json.loads(previous.read_text())
            if saved.get('private_state') == str(state):
                self.result = saved
                if 'failure' in self.result:
                    self.result.setdefault('previous_failures', []).append(self.result.pop('failure'))
        self.http = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def record(self, label, **data):
        entry = {'check': label, 'time_ms': int(time.time() * 1000), **data}
        self.result['checks'].append(entry)
        self.save()
        print(json.dumps(entry), flush=True)

    def save(self):
        write_json(TARGET / (LOG_PREFIX + '-result.json'), self.result)

    def setup(self):
        if hashlib.sha256(PAPER.read_bytes()).hexdigest() != PAPER_SHA256:
            raise ValueError('Pinned Paper asset changed')
        self.result['artifacts'] = {
            str(path.relative_to(BASE)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in [DRIVER, PAPER, PLUGIN]}
        metadata = self.state / 'fixture.json'
        if metadata.exists():
            self.meta = json.loads(metadata.read_text())
            self.record('existing isolated fixture loaded')
            return
        identities = {}
        for member in ['host', 'operator', 'oracle', 'active', 'idle', 'unwitnessed']:
            identities[member] = run([DRIVER, 'keygen', '--out', self.state / (member + '.key')])
        founder = json.loads(run([DRIVER, 'trust', 'founder', '--member', 'host',
                                  '--club', CLUB, '--peer', identities['host']]))
        genesis = {'federation': 'activity-live-acceptance', 'founders': [founder], 'quorum': 1}
        write_json(self.state / 'identity-genesis.json', genesis)
        identity_hash = run([DRIVER, 'trust', 'digest', '--genesis', self.state / 'identity-genesis.json'])
        binding = {'genesis': identity_hash, 'namespace': 'application',
                   'service': 'application', 'club': CLUB, 'audience': identities['host']}
        write_json(self.state / 'binding.json', binding)
        application_hash = run([DRIVER, 'business-genesis', '--binding', self.state / 'binding.json',
                                '--out', self.state / 'application-genesis.json'])
        profiles = {name: {'id': uuid.uuid4().hex, 'name': 'Activity' + name.capitalize()}
                    for name in ['active', 'idle', 'unwitnessed']}
        # Profile names are kept within the game login limits.
        profiles['unwitnessed']['name'] = 'ActivityDirect'
        service = str(uuid.uuid4())
        ports = {name: port() for name in ['host', 'paper', 'oracle', 'rcon']}
        secret = secrets.token_hex(32)
        password = secrets.token_hex(32)
        (self.state / 'forwarding.key').write_text(secret)
        (self.state / 'probe.token').write_text(secrets.token_hex(32))
        (self.state / 'rcon.password').write_text(password)
        settings = self.state / 'paper-config'
        settings.mkdir()
        (settings / 'paper-global.yml').write_text(
            'proxies:\n  velocity:\n    enabled: true\n    online-mode: false\n    secret: "' + secret + '"\n')
        properties = self.state / 'server.properties'
        properties.write_text(
            f'server-ip=127.0.0.1\nserver-port={ports["paper"]}\nonline-mode=false\n'
            'white-list=false\nenforce-whitelist=false\n'
            'enforce-secure-profile=false\nlevel-type=minecraft:flat\n'
            'level-name=activity-acceptance\nview-distance=2\nsimulation-distance=2\n'
            'max-players=8\nspawn-protection=0\ngamemode=creative\nforce-gamemode=true\n'
            'generate-structures=false\nallow-nether=false\nnetwork-compression-threshold=256\n'
            f'enable-rcon=true\nrcon.port={ports["rcon"]}\nrcon.password={password}\n')
        # The host validates this path. The actual secret-bearing file stays in private state.
        properties_link = TARGET / 'server.properties'
        if properties_link.exists() or properties_link.is_symlink():
            raise FileExistsError('The existing target server.properties is in use')
        properties_link.symlink_to(properties)
        (TARGET / 'eula.txt').write_text('eula=true\n')
        plugins = TARGET / 'plugins'
        plugins.mkdir(exist_ok=True)
        plugin_link = plugins / 'union-paper-scoring.jar'
        if plugin_link.exists() or plugin_link.is_symlink():
            raise FileExistsError('The target plugin path is in use')
        plugin_link.symlink_to(PLUGIN)
        plugin_settings = plugins / 'UnionScoring'
        plugin_settings.mkdir(exist_ok=True)
        (plugin_settings / 'config.yml').write_text(
            'scoring:\n  enabled: false\nactivity:\n  enabled: true\n'
            f'  source: {SOURCE}\n  endpoint: http://127.0.0.1:{ports["oracle"]}\n'
            '  token_env: UNION_ACTIVITY_TOKEN\n')
        java = [JAVA, '-Djava.io.tmpdir=' + str(TARGET), '-Xms256M', '-Xmx1024M',
                '-XX:ActiveProcessorCount=2', '-jar', PAPER, '--nogui', '--nojline',
                '--config', properties, '--paper-dir', settings, '--universe', self.state / 'worlds']
        command = shlex.join([str(a) for a in java])
        config = {'node': {'key': str(self.state / 'host.key'),
                           'listen': [f'/ip4/127.0.0.1/tcp/{ports["host"]}']}, 'services': {
            'identity': {'genesis': str(self.state / 'identity-genesis.json'),
                         'genesis_hash': identity_hash, 'log': str(self.state / 'identity.jsonl'),
                         'writer': True, 'max_staleness_seconds': 60},
            'governance': {'genesis': str(self.state / 'application-genesis.json'),
                           'journal': str(self.state / 'application-journal'), 'binding': binding},
            'activity_oracle': {'bind': f'127.0.0.1:{ports["oracle"]}',
                                'key': str(self.state / 'oracle.key'),
                                'spool': str(self.state / 'activity-pending.json'),
                                'evidence_directory': str(self.state / 'activity-evidence'),
                                'probes': [{'source': SOURCE, 'service': service,
                                            'token': str(self.state / 'probe.token')}]},
            'member_rooms': [{'service': service, 'name': 'Activity acceptance Paper',
                              'forwarding_secret': str(self.state / 'forwarding.key'),
                              'club': CLUB, 'join_clubs': [CLUB], 'instance': {
                                  'id': 'activity-live-paper', 'directory': str(TARGET),
                                  'backend': f'127.0.0.1:{ports["paper"]}', 'server': {
                                      'nickname': 'Activity acceptance Paper', 'start_command': command,
                                      'stop_command': 'stop', 'server_type': 'minecraft/java',
                                      'input_encoding': 'utf-8', 'output_encoding': 'utf-8',
                                      'auto_restart': False, 'auto_restart_max_times': 0, 'rcon': None,
                                      'java_path': str(JAVA), 'isolated_tmpdir': False,
                                      'jvm_properties': []}}}]}}
        write_json(self.state / 'host.json', config)
        address = f'/ip4/127.0.0.1/tcp/{ports["host"]}/p2p/{identities["host"]}'
        self.meta = {'identities': identities, 'profiles': profiles, 'ports': ports,
                     'service': service, 'identity_hash': identity_hash,
                     'application_hash': application_hash, 'address': address}
        write_json(metadata, self.meta)
        self.record('isolated single-host deployment prepared', application_hash=application_hash,
                    service=service, protocol=777)

    def spawn(self, args, label):
        path = TARGET / (LOG_PREFIX + '-' + label + '.log')
        handle = path.open('a')
        self.handles.append(handle)
        env = os.environ | {'UNION_ACTIVITY_TOKEN': (self.state / 'probe.token').read_text().strip()}
        process = subprocess.Popen([str(a) for a in args], stdout=handle, stderr=subprocess.STDOUT,
                                   env=env, start_new_session=True)
        return process, path

    def start(self):
        self.generation += 1
        log = TARGET / (LOG_PREFIX + '-host-' + str(self.generation) + '.log')
        offset = log.stat().st_size if log.exists() else 0
        self.host, log = self.spawn([DRIVER, 'run', '--config', self.state / 'host.json'],
                                    'host-' + str(self.generation))
        deadline = time.monotonic() + 150
        while time.monotonic() < deadline:
            if self.host.poll() is not None:
                raise RuntimeError('Host exited: ' + log.read_text()[-4500:])
            if '"room:' in log.read_text()[offset:]:
                for path in Path('/proc').glob('[0-9]*/cmdline'):
                    try:
                        arguments = path.read_bytes().split(b'\0')
                        if (str(PAPER).encode() in arguments
                                and str(self.state / 'server.properties').encode() in arguments):
                            self.paper_group = os.getpgid(int(path.parent.name))
                    except (OSError, ProcessLookupError):
                        continue
                if self.paper_group is None:
                    raise RuntimeError('Owned Paper process group not found')
                self.rcon = Rcon(('127.0.0.1', self.meta['ports']['rcon']),
                                 (self.state / 'rcon.password').read_text())
                self.record('host and real Paper ready', generation=self.generation)
                return
            time.sleep(0.25)
        raise TimeoutError('Host/Paper startup timed out: ' + log.read_text()[-4500:])

    def trust(self, action, signers):
        self.sequence += 1
        cache = ['--genesis', self.state / 'identity-genesis.json',
                 '--genesis-hash', self.meta['identity_hash'], '--log', self.state / 'operator-cache.jsonl']
        target = ['--key', self.state / 'operator.key', '--address', self.meta['address'],
                  '--peer', self.meta['identities']['host']]
        run([DRIVER, 'trust', 'sync', *cache, *target])
        action_path = self.state / ('action-' + str(self.sequence) + '.json')
        write_json(action_path, action)
        record = self.state / ('record-' + str(self.sequence) + '.json')
        run([DRIVER, 'trust', 'draft', *cache, '--action', action_path, '--out', record])
        for index, signer in enumerate(signers):
            signed = self.state / (f'signed-{self.sequence}-{index}.json')
            run([DRIVER, 'trust', 'sign', '--key', self.state / (signer + '.key'),
                 '--record', record, '--out', signed])
            record = signed
        run([DRIVER, 'trust', 'submit', *cache, *target, '--record', record])

    def application(self, action=None):
        identity = {'genesis': json.loads((self.state / 'identity-genesis.json').read_text()),
                    'genesis_hash': self.meta['identity_hash'],
                    'log': str(self.state / 'application-client-cache.jsonl'),
                    'address': self.meta['address'], 'peer': self.meta['identities']['host']}
        path = self.state / 'application-input.json'
        write_json(path, {'identity': identity, 'address': self.meta['address'],
                          'peer': self.meta['identities']['host'],
                          'genesis_hash': self.meta['application_hash'],
                          'revision': None, 'action': action})
        return json.loads(run([DRIVER, 'application', '--key', self.state / 'operator.key', '--input', path]))

    def configure(self):
        if not (self.state / 'registered').exists():
            self.trust({'type': 'register_service', 'service': 'application',
                        'audience': self.meta['identities']['host'], 'club': CLUB}, ['host'])
            for member in ['operator', 'oracle', 'active', 'idle', 'unwitnessed']:
                self.trust({'type': 'confirm_member', 'member': member, 'club': CLUB,
                            'device': self.meta['identities'][member], 'evidence': 'manual_verification',
                            'verifier': None}, ['host', member])
            for member, permission in [('operator', 'admin'), ('oracle', 'write')]:
                self.trust({'type': 'grant_permission', 'id': str(uuid.uuid4()), 'member': member,
                            'service': 'application', 'permission': permission}, ['host'])
            for member, profile in self.meta['profiles'].items():
                self.trust({'type': 'bind_game_profile', 'member': member, 'club': CLUB,
                            'profile': profile['id']}, ['host', member])
            (self.state / 'registered').touch()
        snapshot = self.application()['state']
        self.baseline = snapshot['organization']['points'].get(CLUB, {}).get('active', 0)
        self.application({'type': 'organization.activity_policy',
                          'policy': {'daily_member_cap': self.baseline + 15}})
        self.application({'type': 'organization.oracle_source', 'id': SOURCE, 'source': {
            'title': 'Real Paper activity acceptance', 'club': CLUB,
            'oracle_device': self.meta['identities']['oracle'], 'service': self.meta['service'],
            'weight_bps': 10_000, 'points_per_slice': 10, 'max_bonus_per_slice': 0,
            'daily_source_cap': 1000, 'enabled': True}})
        self.record('signed identity and points policy configured', baseline=self.baseline,
                    member_cap=self.baseline + 15)

    def connect_players(self):
        self.rcon.command('forceload add -16 -16 16 16')
        deadline = time.monotonic() + 30
        while True:
            response = self.rcon.command(f'fill -8 {PLATFORM_Y} -8 8 {PLATFORM_Y} 8 minecraft:stone')
            if 'not loaded' not in response:
                break
            if time.monotonic() > deadline:
                raise TimeoutError('Paper did not load the gameplay arena')
            time.sleep(0.5)
        for command in [f'fill -8 {PLATFORM_Y} -8 8 {PLATFORM_Y} 8 minecraft:stone',
                        f'setblock 0 {BLOCK_Y} 2 minecraft:lever[face=floor,facing=north]',
                        f'setworldspawn 0 {BLOCK_Y} 0']:
            self.rcon.command(command)
        for member in ['active', 'idle', 'unwitnessed']:
            forwarding_key = None
            if member == 'unwitnessed':
                game_port = self.meta['ports']['paper']
                forwarding_key = (self.state / 'forwarding.key').read_bytes().strip()
            else:
                game_port = port()
                process, log = self.spawn([DRIVER, 'proxy', '--key', self.state / (member + '.key'),
                                            '--address', self.meta['address'],
                                            '--peer', self.meta['identities']['host'],
                                            '--service', self.meta['service'],
                                            '--bind', f'127.0.0.1:{game_port}'],
                                           member + '-proxy-' + str(self.generation))
                self.proxies.append(process)
                deadline = time.monotonic() + 30
                while 'local game proxy ready' not in log.read_text():
                    if process.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError('Game proxy failed: ' + log.read_text()[-2000:])
                    time.sleep(0.1)
            client = ActivityClient(('127.0.0.1', game_port), self.meta['profiles'][member],
                                    active=member != 'idle', forwarding_key=forwarding_key)
            self.clients.append(client)
            self.rcon.command(f'tp {client.profile["name"]} 0.5 {BLOCK_Y} 0.5')
        for _ in range(30):
            self.check_clients()
            time.sleep(0.5)
        self.record('three real Paper clients healthy', clients=[c.evidence() for c in self.clients])

    def check_clients(self):
        for client in self.clients:
            client.check()
        if self.host.poll() is not None:
            raise RuntimeError('Host stopped during gameplay')

    def completed_window(self):
        # Every player must have joined before the beginning of this full real-time window.
        start = (int(time.time() * 1000) // SLICE_MS + 1) * SLICE_MS
        end = start + SLICE_MS
        self.record('waiting for complete real-time window', start_ms=start, end_ms=end)
        next_progress = time.monotonic() + 30
        deadline = end / 1000 + 45
        while time.time() < deadline:
            self.check_clients()
            pending_path = self.state / 'activity-pending.json'
            if pending_path.exists():
                pending = json.loads(pending_path.read_text()).get(SOURCE, {})
                for item in pending.get('slices', []):
                    if item['report']['window_start_ms'] == start:
                        players = item['report']['players']
                        active = self.meta['profiles']['active']['id']
                        idle = self.meta['profiles']['idle']['id']
                        direct = self.meta['profiles']['unwitnessed']['id']
                        active_metrics = players[active]
                        assert active_metrics['movement_steps'] >= 8, active_metrics
                        assert active_metrics['distinct_positions'] >= 4, active_metrics
                        assert active_metrics['look_samples'] >= 8, active_metrics
                        assert active_metrics['world_interactions'] >= 2, active_metrics
                        assert active_metrics['yaw_variance_milli'] >= 25_000, active_metrics
                        assert players[idle]['world_interactions'] == 0, players[idle]
                        assert players[direct]['world_interactions'] >= 2, players[direct]
                        assert item['members'] == {active: 'active', idle: 'idle'}, item['members']
                        self.record('Paper report durably acknowledged with gateway witnesses',
                                    report=item['report'], admitted_members=item['members'])
                        return item['report']
            if time.monotonic() >= next_progress:
                print(json.dumps({'waiting_until_ms': end, 'now_ms': int(time.time() * 1000),
                                  'client_packets': [c.evidence() for c in self.clients]}), flush=True)
                next_progress = time.monotonic() + 30
            time.sleep(0.5)
        raise TimeoutError('Paper did not deliver the full activity window')

    def request(self, operation, body=None):
        request = urllib.request.Request(
            f'http://127.0.0.1:{self.meta["ports"]["oracle"]}/v1/activity/{SOURCE}/' + operation,
            data=json.dumps(body).encode() if body is not None else None,
            headers={'Authorization': 'Bearer ' + (self.state / 'probe.token').read_text().strip(),
                     'Content-Type': 'application/json'})
        try:
            with self.http.open(request, timeout=15) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.read()

    def close_clients(self):
        for client in self.clients:
            client.close()
        self.clients.clear()
        for process in self.proxies:
            self.stop_process(process)
        self.proxies.clear()

    @staticmethod
    def stop_process(process):
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=35)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=10)

    def crash(self):
        self.close_clients()
        self.rcon.close()
        self.rcon = None
        os.killpg(self.host.pid, signal.SIGKILL)
        self.host.wait(timeout=10)
        os.killpg(self.paper_group, signal.SIGKILL)
        self.paper_group = None
        time.sleep(1)
        self.record('host and Paper process group terminated without graceful flush')

    def state_check(self, expected):
        response = self.application()
        state = response['state']
        organization = state['organization']
        assert organization['points'][CLUB]['active'] == expected, organization['points']
        assert organization['points'].get(CLUB, {}).get('idle', 0) == 0, organization['points']
        assert organization['points'].get(CLUB, {}).get('unwitnessed', 0) == 0, organization['points']
        assert state.get('files', {}) == {}, state.get('files')
        return response

    def execute(self):
        self.setup()
        self.start()
        self.configure()
        self.connect_players()
        report = self.completed_window()
        before = self.application()
        assert before['state']['organization']['points'].get(CLUB, {}).get('active', 0) == self.baseline
        self.crash()
        self.start()
        assert self.request('flush', {})[0] == 204
        recovered = self.state_check(self.baseline + 10)
        write_json(TARGET / (LOG_PREFIX + '-recovered-snapshot.json'), recovered)
        self.record('acknowledged evidence recovered and settled exactly once',
                    balance=self.baseline + 10, revision=recovered['state']['revision'])
        assert self.request('slice', report)[0] == 204
        altered = json.loads(json.dumps(report))
        altered['players'][self.meta['profiles']['active']['id']]['movement_steps'] += 1
        assert self.request('slice', altered)[0] == 409
        unchanged = self.state_check(self.baseline + 10)
        assert unchanged['state']['revision'] == recovered['state']['revision']
        self.record('exact report retry acknowledged and altered retry rejected without mint')
        for receipt in recovered['state']['organization']['activity_receipts'].values():
            cid = receipt['evidence']
            status, body = self.request('evidence/' + cid)
            assert status == 200
            evidence = json.loads(body)
            assert any(s['report'] == report for s in evidence['slices'])
        self.record('CID telemetry fetched through authenticated evidence endpoint')
        self.connect_players()
        second = self.completed_window()
        assert self.request('flush', {})[0] == 204
        capped = self.state_check(self.baseline + 15)
        write_json(TARGET / (LOG_PREFIX + '-capped-snapshot.json'), capped)
        assert self.request('slice', second)[0] == 204
        self.state_check(self.baseline + 15)
        self.record('second real window obeyed member cap; idle and direct players remained uncredited',
                    balance=self.baseline + 15, revision=capped['state']['revision'])
        self.close_clients()
        self.rcon.close()
        self.rcon = None
        self.stop_process(self.host)
        assert self.host.returncode == 0
        self.start()
        replayed = self.state_check(self.baseline + 15)
        assert replayed['state']['organization'] == capped['state']['organization']
        self.record('graceful shutdown and journal replay preserved points and receipts',
                    revision=replayed['state']['revision'])
        self.result['passed'] = True
        self.save()

    def close(self):
        self.close_clients()
        if self.rcon is not None:
            self.rcon.close()
        if self.host is not None:
            self.stop_process(self.host)
        for handle in self.handles:
            handle.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    state = args.state
    if state is None:
        root = Path(os.environ['ACTIVITY_ACCEPTANCE_STATE_ROOT']).resolve()
        state = Path(tempfile.mkdtemp(prefix='activity-live-', dir=root))
    acceptance = Acceptance(state.resolve())
    try:
        acceptance.execute()
    except Exception as error:
        acceptance.result['failure'] = str(error)
        acceptance.save()
        raise
    finally:
        acceptance.close()


if __name__ == '__main__':
    main()
