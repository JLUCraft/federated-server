"""Real Paper league gateway acceptance with isolated, generated test identities.

Only the existing project target holds downloaded assets and process output. Private
keys, host settings, Paper settings, and worlds stay under an external state root.
The selected Paper artifact is resolved and verified against current official metadata.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
import urllib.request
import uuid

from activity_acceptance import Rcon
from minecraft_activity import ActivityClient, PROTOCOL
from minecraft_login import Client, text, varint

BASE = Path(__file__).resolve().parents[3]
TARGET = BASE / 'federated-server/target'
OFFICIAL_METADATA = 'https://fill.papermc.io/v3/projects/paper/versions/26.3/builds/209'
USER_AGENT = 'JLUCraftAcceptance/1.0 (https://github.com/JLUCraft)'
LEAGUE = 'isolated-paper-league'
CLUB = 'paper-test'
TIMEOUT_SECONDS = 60
PAPER_START_SECONDS = 240
RECONNECT_MIN_MS = 1000
RECONNECT_MAX_MS = 3000


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def port():
    with socket.socket() as connection:
        connection.bind(('127.0.0.1', 0))
        return connection.getsockname()[1]


def until(check, seconds=TIMEOUT_SECONDS):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(0.1)
    raise TimeoutError('League acceptance condition timed out')


class LeagueClient(ActivityClient):
    """Reuse the protocol client; observe transfer packets without changing its game flow."""
    def __init__(self, address, profile, transfer_packet):
        self.transferred = threading.Event()
        self.transfer_target = None
        self.transfer_packet = transfer_packet
        super().__init__(address, profile, active=False)

    def _read(self):
        receive = self.client.packet

        def packet():
            packet_id, fields = receive()
            if packet_id == self.transfer_packet:
                self.transfer_target = (fields.blob().decode(), fields.integer())
                self.transferred.set()
            return packet_id, fields

        self.client.packet = packet
        super()._read()

    def close(self):
        try:
            self.client.socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        super().close()


class Acceptance:
    def __init__(self, args):
        self.args = args
        self.processes = []
        self.handles = []
        self.clients = []
        self.rcon = {}
        self.sequence = 0
        self.result_path = TARGET / 'league-proxy-result.json'
        previous = json.loads(self.result_path.read_text()) if args.resume_state else None
        if self.result_path.exists() and not args.resume_state:
            raise FileExistsError('Preserve and review the previous league-proxy result before a new attempt')
        root = args.state_root.resolve(strict=True)
        if root.is_relative_to(BASE) or not root.is_dir():
            raise ValueError('Use an existing private state parent outside the workspace')
        self.state = args.resume_state.resolve(strict=True) if args.resume_state else Path(tempfile.mkdtemp(prefix='league-paper-', dir=root))
        if not self.state.is_relative_to(root):
            raise ValueError('Resume only the isolated state owned by this fixture')
        self.result = {'passed': False, 'scope': 'real Paper league_proxy; no activity or AI',
                       'state_directory': str(self.state), 'events': [], 'processes': [],
                       'runtime': {'java': str(args.java), 'driver': str(args.driver),
                                   'paper': str(args.paper), 'working_directory': str(TARGET)}}
        if previous is not None:
            self.result['prior_attempts'] = [*previous.get('prior_attempts', []), {
                'failure': previous['failure'], 'state_directory': previous['state_directory'],
                'inputs': previous['inputs'], 'processes': previous['processes'],
                'exit_codes': previous['exit_codes'],
                'owned_processes_stopped': previous['owned_processes_stopped'],
                'failure_context': previous.get('failure_context'),
                'connection_diagnostic': previous.get('connection_diagnostic'),
                'phase_diagnostic': previous.get('phase_diagnostic')}]
            self.result['events'] = previous['events']
            self.result['paper_asset'] = previous['paper_asset']
            self.result['paper_runtime_asset_readiness'] = previous['paper_runtime_asset_readiness']
            self.result['shutdown_fixed_diagnostic'] = previous['shutdown_fixed_diagnostic']
            self.result['inputs'] = {**previous['inputs'], str(Path(__file__)): hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                                    str(args.driver): hashlib.sha256(args.driver.read_bytes()).hexdigest()}
        self.log_offsets = {}
        self.ids = {}
        self.profiles = {member: {'id': uuid.uuid4().hex, 'name': 'League' + member.capitalize()}
                         for member in ['alice', 'bob']}
        self.ports = {name: port() for name in ['host', 'waiting', 'arena', 'waiting-rcon', 'arena-rcon',
                                               'alice-proxy', 'bob-proxy']}
        self.service = str(uuid.uuid4())
        self.host = None
        self.host_generation = 0
        self.game_clients = {}
        self.papers = {}
        self.config = None
        self.phase = 'initialization'
        self.pending_record = None
        self.context_path = self.state / 'league-fixture.json'
        self.host_write_permission_id = str(uuid.uuid4())

    def save(self):
        write_json(self.result_path, self.result)

    def record(self, event, **details):
        entry = {'event': event, 'unix_ms': time.time_ns() // 1_000_000, **details}
        self.result['events'].append(entry)
        self.save()
        print(json.dumps(entry), flush=True)

    def invoke(self, *args):
        self.result['last_driver_command'] = list(map(str, args[:2]))
        result = subprocess.run([str(self.args.driver), *map(str, args)],
                                capture_output=True, text=True, timeout=TIMEOUT_SECONDS)
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or 'Acceptance driver command failed')
        return result.stdout.strip()

    def spawn(self, command, label):
        path = TARGET / ('league-proxy-' + label + '.log')
        self.log_offsets[path] = path.stat().st_size if path.exists() else 0
        handle = path.open('a')
        self.handles.append(handle)
        process = subprocess.Popen([str(arg) for arg in command], cwd=TARGET, stdout=handle,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        self.processes.append(process)
        self.result['processes'].append({'label': label, 'pid': process.pid, 'log': str(path)})
        return process, path

    def log_text(self, path):
        with path.open('rb') as handle:
            handle.seek(self.log_offsets[path])
            return handle.read().decode(errors='replace')

    @staticmethod
    def stop(process, stop_signal=signal.SIGTERM):
        if process.poll() is None:
            process.send_signal(stop_signal)
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)

    def assets(self):
        request = urllib.request.Request(OFFICIAL_METADATA, headers={'User-Agent': USER_AGENT})
        with urllib.request.urlopen(request, timeout=30) as response:
            metadata = json.load(response)
        asset = metadata['downloads']['server:default']
        if metadata['id'] != 209:
            raise ValueError('The official response does not describe the selected build')
        paper = self.args.paper.resolve()
        if paper.parent != TARGET:
            raise ValueError('Paper assets must use the existing federated-server target directory')
        expected_hash = asset['checksums']['sha256']
        if paper.exists():
            if paper.stat().st_size != asset['size'] or hashlib.sha256(paper.read_bytes()).hexdigest() != expected_hash:
                raise ValueError('Existing Paper artifact differs from the current official metadata; it was not overwritten')
        else:
            temporary = paper.with_suffix('.download')
            request = urllib.request.Request(asset['url'], headers={'User-Agent': USER_AGENT})
            with urllib.request.urlopen(request, timeout=60) as response, temporary.open('xb') as output:
                shutil.copyfileobj(response, output)
            if temporary.stat().st_size != asset['size'] or hashlib.sha256(temporary.read_bytes()).hexdigest() != expected_hash:
                raise ValueError('Downloaded Paper artifact failed the current official size/checksum')
            temporary.rename(paper)
        self.result['paper_asset'] = {'metadata_url': OFFICIAL_METADATA, 'metadata': metadata,
                                      'downloaded_sha256': hashlib.sha256(paper.read_bytes()).hexdigest(),
                                      'size_bytes': paper.stat().st_size, 'path': str(paper)}
        self.result['inputs'] = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in [
            self.args.driver, Path(__file__), Path(__file__).with_name('minecraft_activity.py'),
            Path(__file__).with_name('minecraft_login.py'), Path(__file__).with_name('activity_acceptance.py'),
            BASE / 'federated-server/protocol/26.3-packets.json']}
        self.record('official selected Paper artifact ready', size_bytes=paper.stat().st_size)

    def prepare(self):
        for member in ['host', 'operator', 'alice', 'bob']:
            key = self.state / (member + '.key')
            self.ids[member] = self.invoke('keygen', '--out', key)
            if key.stat().st_mode & 0o077:
                raise ValueError('Test private key must be owner-only')
        founder = json.loads(self.invoke('trust', 'founder', '--member', 'operator', '--club', CLUB,
                                         '--peer', self.ids['operator']))
        genesis = {'federation': 'isolated-real-paper-league', 'founders': [founder], 'quorum': 1}
        write_json(self.state / 'identity-genesis.json', genesis)
        self.identity_hash = self.invoke('trust', 'digest', '--genesis', self.state / 'identity-genesis.json')
        binding = {'genesis': self.identity_hash, 'namespace': 'application', 'service': 'application',
                   'club': CLUB, 'audience': self.ids['host']}
        write_json(self.state / 'binding.json', binding)
        self.application_hash = self.invoke('business-genesis', '--binding', self.state / 'binding.json',
                                            '--out', self.state / 'application-genesis.json')
        self.address = f'/ip4/127.0.0.1/udp/{self.ports["host"]}/quic-v1/p2p/{self.ids["host"]}'
        self.config = {'node': {'key': str(self.state / 'host.key'),
                                'listen': [self.address.rsplit('/p2p/', 1)[0]]}, 'services': {
            'identity': {'genesis': str(self.state / 'identity-genesis.json'),
                         'genesis_hash': self.identity_hash, 'log': str(self.state / 'identity.jsonl'),
                         'writer': True, 'max_staleness_seconds': 60},
            'governance': {'genesis': str(self.state / 'application-genesis.json'),
                           'journal': str(self.state / 'application-journal'), 'binding': binding}}}
        self.start_host()
        self.trust({'type': 'confirm_member', 'member': 'host', 'club': CLUB,
                    'device': self.ids['host'], 'evidence': 'isolated_test_host',
                    'verifier': None}, ['operator', 'host'])
        self.trust({'type': 'register_service', 'service': 'application',
                    'audience': self.ids['host'], 'club': CLUB}, ['operator', 'host'])
        self.trust({'type': 'grant_permission', 'id': str(uuid.uuid4()), 'member': 'operator',
                    'service': 'application', 'permission': 'admin'}, ['operator'])
        self.complete_registration()

    def complete_registration(self):
        self.trust({'type': 'grant_permission', 'id': self.host_write_permission_id, 'member': 'host',
                    'service': 'application', 'permission': 'write'}, ['operator'])
        for member in ['alice', 'bob']:
            self.trust({'type': 'confirm_member', 'member': member, 'club': CLUB,
                        'device': self.ids[member], 'evidence': 'isolated_test_identity',
                        'verifier': None}, ['operator', member])
            self.trust({'type': 'bind_game_profile', 'member': member, 'club': CLUB,
                        'profile': self.profiles[member]['id']}, ['operator', member])
            permission_id = str(uuid.uuid5(uuid.UUID(self.service), member + ':application:write'))
            self.trust({'type': 'grant_permission', 'id': permission_id, 'member': member,
                        'service': 'application', 'permission': 'write'}, ['operator'])
        response = self.application()
        if LEAGUE not in response['state']['leagues']:
            response = self.application('operator', {'type': 'create_league', 'league': LEAGUE,
                                        'rules': {'cross_club': False, 'seats': 1,
                                                  'reconnect_min_ms': RECONNECT_MIN_MS,
                                                  'reconnect_max_ms': RECONNECT_MAX_MS},
                                        'host': self.ids['host'], 'scorer': self.ids['operator']})
        if 'team' not in response['state']['leagues'][LEAGUE]['teams']:
            response = self.application('alice', {'type': 'create_team', 'league': LEAGUE, 'team': 'team'})
        team = response['state']['leagues'][LEAGUE]['teams']['team']
        if 'bob' not in team['members']:
            if 'bob' not in team['invited']:
                self.application('alice', {'type': 'invite', 'league': LEAGUE, 'team': 'team', 'member': 'bob'})
            response = self.application('bob', {'type': 'accept', 'league': LEAGUE, 'team': 'team'})
        if not response['state']['leagues'][LEAGUE]['teams']['team']['registered']:
            self.application('alice', {'type': 'register', 'league': LEAGUE, 'team': 'team'})
        self.stop(self.host)
        if self.host.returncode != 0:
            raise RuntimeError('Identity/application setup host did not exit cleanly')
        self.save_context(registration_complete=True)
        self.record('isolated league and registered two-member team prepared')

    def save_context(self, registration_complete):
        write_json(self.context_path, {'ids': self.ids, 'profiles': self.profiles,
                                       'ports': self.ports, 'service': self.service,
                                       'host_write_permission_id': self.host_write_permission_id,
                                       'registration_complete': registration_complete})

    def resume_prepare(self):
        self.phase = 'resume audited identity checkpoint'
        self.config = json.loads((self.state / 'host.json').read_text())
        context = json.loads(self.context_path.read_text()) if self.context_path.exists() else None
        if context:
            self.ids = context['ids']
            self.profiles = context['profiles']
            self.ports = context['ports']
            self.service = context['service']
            self.host_write_permission_id = context['host_write_permission_id']
        else:
            self.ids = {member: json.loads(self.invoke('inspect-key', '--key', self.state / (member + '.key')))['peer']
                        for member in ['host', 'operator', 'alice', 'bob']}
        self.identity_hash = self.config['services']['identity']['genesis_hash']
        self.application_hash = self.invoke('business-genesis', '--binding', self.state / 'binding.json')
        self.address = self.config['node']['listen'][0] + '/p2p/' + self.ids['host']
        self.ports['host'] = int(self.address.split('/udp/')[1].split('/')[0])
        if context and context['registration_complete']:
            self.record('reused completed identity and team registration')
            return
        self.save_context(registration_complete=False)
        self.start_host()
        self.pending_record = self.state / 'signed-3-0.json'
        pending = json.loads(self.pending_record.read_text())
        records = [json.loads(line) for line in (self.state / 'identity.jsonl').read_text().splitlines()]
        if pending not in records:
            if records[-1]['sequence'] + 1 != pending['sequence']:
                raise ValueError('Review the current checkpoint before submitting the retained record')
            self.phase = 'submit retained unique signed record once'
            cache = ['--genesis', self.state / 'identity-genesis.json', '--genesis-hash', self.identity_hash,
                     '--log', self.state / 'host-cache.jsonl']
            target = ['--key', self.state / 'operator.key', '--address', self.address, '--peer', self.ids['host']]
            self.invoke('trust', 'submit', *cache, *target, '--record', self.pending_record)
            records = [json.loads(line) for line in (self.state / 'identity.jsonl').read_text().splitlines()]
            if pending not in records:
                raise AssertionError('Retained signed record was not committed')
            self.record('retained signed identity record committed once', sequence=pending['sequence'])
        else:
            self.record('reused audited successful retained-record submission', sequence=pending['sequence'])
        self.sequence = records[-1]['sequence']
        self.pending_record = None
        self.complete_registration()

    def start_host(self):
        self.host_generation += 1
        write_json(self.state / 'host.json', self.config)
        self.host, log = self.spawn([self.args.driver, 'run', '--config', self.state / 'host.json'],
                                    'host-' + str(self.host_generation))

        def ready():
            if self.host.poll() is not None:
                raise RuntimeError('Isolated league host exited: ' + self.log_text(log)[-1500:])
            return any(line.startswith('{"peer":') for line in self.log_text(log).splitlines())
        until(ready)

    def trust(self, action, signers):
        self.phase = 'identity sync/draft/sign/submit: ' + action['type']
        records = [json.loads(line) for line in (self.state / 'identity.jsonl').read_text().splitlines()]
        if any(record['action'] == action for record in records):
            self.sequence = records[-1]['sequence']
            return
        self.sequence = records[-1]['sequence'] + 1
        cache = ['--genesis', self.state / 'identity-genesis.json', '--genesis-hash', self.identity_hash,
                 '--log', self.state / 'host-cache.jsonl']
        target = ['--key', self.state / 'operator.key', '--address', self.address, '--peer', self.ids['host']]
        self.invoke('trust', 'sync', *cache, *target)
        action_path = self.state / f'action-{self.sequence}.json'
        write_json(action_path, action)
        record = self.state / f'record-{self.sequence}.json'
        self.invoke('trust', 'draft', *cache, '--action', action_path, '--out', record)
        for index, member in enumerate(signers):
            signed = self.state / f'signed-{self.sequence}-{index}.json'
            self.invoke('trust', 'sign', '--key', self.state / (member + '.key'), '--record', record, '--out', signed)
            record = signed
        self.pending_record = record
        self.invoke('trust', 'submit', *cache, *target, '--record', record)
        self.pending_record = None

    def application(self, member='operator', action=None):
        self.phase = 'application ' + (action['type'] if action else 'snapshot')
        identity = {'genesis': json.loads((self.state / 'identity-genesis.json').read_text()),
                    'genesis_hash': self.identity_hash, 'log': str(self.state / (member + '-app-cache.jsonl')),
                    'address': self.address, 'peer': self.ids['host']}
        path = self.state / (member + '-input.json')
        write_json(path, {'identity': identity, 'address': self.address, 'peer': self.ids['host'],
                          'genesis_hash': self.application_hash, 'revision': None, 'action': action})
        return json.loads(self.invoke('application', '--key', self.state / (member + '.key'), '--input', path))

    def league(self):
        return self.application()['state']['leagues'][LEAGUE]

    def start_paper(self, room):
        self.phase = room + ' Paper startup'
        settings = self.state / (room + '-paper')
        properties = self.state / (room + '.properties')
        if self.args.finish_only:
            entries = dict(line.split('=', 1) for line in properties.read_text().splitlines()
                           if '=' in line and not line.startswith('#'))
            password = entries['rcon.password']
        else:
            settings.mkdir()
            forwarding = secrets.token_hex(32)
            password = secrets.token_hex(32)
            (self.state / (room + '.secret')).write_text(forwarding)
            (settings / 'paper-global.yml').write_text(
                'proxies:\n  velocity:\n    enabled: true\n    online-mode: false\n    secret: "' + forwarding + '"\n')
            properties.write_text(
                f'server-ip=127.0.0.1\nserver-port={self.ports[room]}\nonline-mode=false\n'
                f'enable-rcon=true\nrcon.port={self.ports[room + "-rcon"]}\nrcon.password={password}\n'
                'enforce-secure-profile=false\nwhite-list=false\nspawn-protection=0\ngamemode=creative\n'
                'generate-structures=false\nallow-nether=false\nlevel-type=minecraft:flat\n'
                'view-distance=2\nsimulation-distance=2\nmax-players=4\nnetwork-compression-threshold=256\n')
        eula = TARGET / 'eula.txt'
        if not eula.exists():
            eula.write_text('eula=true\n')
        self.papers[room], log = self.spawn([
            self.args.java, '-Djava.io.tmpdir=' + str(TARGET), '-Xms256M', '-Xmx768M',
            '-XX:ActiveProcessorCount=2', '-jar', self.args.paper, '--nogui', '--nojline',
            '--config', properties, '--paper-dir', settings, '--universe', self.state / (room + '-worlds'),
            '--plugins', self.state / (room + '-plugins')], room + '-paper')

        def ready():
            if self.papers[room].poll() is not None:
                raise RuntimeError(room + ' Paper exited before readiness: ' + self.log_text(log)[-2000:])
            return 'Done (' in self.log_text(log)
        until(ready, PAPER_START_SECONDS)
        self.rcon[room] = Rcon(('127.0.0.1', self.ports[room + '-rcon']), password)
        self.record('real Paper backend ready', room=room, port=self.ports[room])

    def online(self, room, member):
        return self.profiles[member]['name'] in self.rcon[room].command('list')

    def connect(self, member):
        self.phase = 'real Paper login through league gateway: ' + member
        packets = json.loads((BASE / 'federated-server/protocol/26.3-packets.json').read_text())
        transfer = packets['play']['clientbound']['minecraft:transfer']['protocol_id']
        client = LeagueClient(('127.0.0.1', self.ports[member + '-proxy']), self.profiles[member], transfer)
        self.clients.append(client)
        self.game_clients[member] = client
        return client

    def await_transfer(self, member):
        client = self.game_clients[member]
        if not client.transferred.wait(TIMEOUT_SECONDS):
            raise TimeoutError(member + ' did not receive a real transfer packet: ' + str(client.error))
        if client.transfer_target != ('127.0.0.1', self.ports[member + '-proxy']):
            raise ValueError('Transfer did not point back to the authenticated local proxy')
        client.close()
        self.record('real transfer packet received', member=member, target=client.transfer_target)

    def reject_substitution(self):
        client = Client(('127.0.0.1', self.ports['alice-proxy']))
        try:
            client.send(b'\0' + varint(PROTOCOL) + text('localhost')
                        + struct.pack('>H', self.ports['alice-proxy']) + b'\2')
            client.send(b'\0' + text(self.profiles['bob']['name']) + uuid.UUID(self.profiles['bob']['id']).bytes)
            packet, _ = client.packet()
            if packet != 0:
                raise AssertionError('UUID substitution reached a login-success path')
        except (EOFError, ConnectionError):
            pass
        finally:
            client.close()
        self.record('authenticated identity cannot substitute another player UUID')

    def execute(self):
        if self.args.resume_state:
            self.record('reused successful assets and audited identity checkpoint')
            self.resume_prepare()
        else:
            self.assets()
            self.prepare()
        self.start_paper('waiting')
        self.start_paper('arena')
        backend = lambda room: {'endpoint': {'transport': 'local', 'address': f'127.0.0.1:{self.ports[room]}'},
                                'forwarding_secret': str(self.state / (room + '.secret'))}
        self.config['services']['league_proxy'] = {'key': str(self.state / 'host.key'), 'config': {
            'league': LEAGUE, 'service': self.service, 'waiting': backend('waiting'), 'arena': backend('arena')}}
        self.start_host()
        until(lambda: not self.league().get('infrastructure_down', False))
        for member in ['alice', 'bob']:
            process, log = self.spawn([self.args.driver, 'proxy', '--key', self.state / (member + '.key'),
                                       '--address', self.address, '--peer', self.ids['host'],
                                       '--service', self.service, '--bind', f'127.0.0.1:{self.ports[member + "-proxy"]}'],
                                      member + '-proxy')
            until(lambda: 'local game proxy ready' in self.log_text(log) if process.poll() is None else False)
        if self.args.finish_only:
            if self.league()['phase'] != 'Finished':
                raise ValueError('Finish-only validation requires the retained finished league')
            for member in ['alice', 'bob']:
                self.connect(member)
            until(lambda: all(self.online('waiting', member) for member in ['alice', 'bob']))
            if any(self.online('arena', member) for member in ['alice', 'bob']):
                raise AssertionError('A finished-league player entered the arena')
            self.result['final_league'] = self.league()
            self.result['passed'] = True
            self.result['retained_stages'] = [
                'two forwarded profiles reached real Paper waiting room',
                'authenticated identity cannot substitute another player UUID',
                'selected player entered real arena and teammate remained waiting',
                'real disconnect substituted teammate; returning player stayed in waiting room']
            self.record('finished league accepts both returning players in real waiting backend',
                        scope='finish-only; earlier successful unchanged phases retained')
            return
        self.reject_substitution()
        for member in ['alice', 'bob']:
            self.connect(member)
        until(lambda: all(self.online('waiting', member) for member in ['alice', 'bob']))
        if any(self.online('arena', member) for member in ['alice', 'bob']):
            raise AssertionError('A registered player entered the arena before league start')
        self.record('two forwarded profiles reached real Paper waiting room')
        self.application('operator', {'type': 'start', 'league': LEAGUE, 'seed': list(secrets.token_bytes(32))})
        selected = self.league()['seats']['team'][0]['player']
        standby = 'bob' if selected == 'alice' else 'alice'
        self.await_transfer(selected)
        self.connect(selected)
        until(lambda: self.online('arena', selected) and self.online('waiting', standby))
        self.record('selected player entered real arena and teammate remained waiting', selected=selected, standby=standby)
        self.game_clients[selected].close()
        self.await_transfer(standby)
        self.connect(standby)
        until(lambda: self.online('arena', standby) and self.league()['seats']['team'][0]['player'] == standby)
        self.connect(selected)
        until(lambda: self.online('waiting', selected))
        if self.league()['seats']['team'][0]['player'] != standby:
            raise AssertionError('Returning player replaced the active substitute')
        self.record('real disconnect substituted teammate; returning player stayed in waiting room',
                    selected=selected, active_substitute=standby)
        self.application('operator', {'type': 'finish', 'league': LEAGUE})
        self.await_transfer(standby)
        self.connect(standby)
        until(lambda: all(self.online('waiting', member) for member in ['alice', 'bob']))
        if self.league()['phase'] != 'Finished':
            raise AssertionError('League did not reach Finished')
        self.result['final_league'] = self.league()
        self.result['passed'] = True
        self.record('finished league returned both players to real waiting backend')

    def close(self):
        for client in self.clients:
            client.close()
        for room, client in self.rcon.items():
            try:
                client.command('stop')
            except (EOFError, OSError):
                pass
            client.close()
            try:
                self.papers[room].wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.result.setdefault('cleanup_timeouts', []).append(room)
        for process, info in reversed(list(zip(self.processes, self.result['processes']))):
            self.stop(process, signal.SIGINT if info['label'].endswith('-proxy') else signal.SIGTERM)
        for handle in self.handles:
            handle.close()
        self.result['owned_processes_stopped'] = all(process.poll() is not None for process in self.processes)
        self.result['owned_processes_clean_exit'] = all(process.returncode == 0 for process in self.processes)
        self.result['exit_codes'] = {str(process.pid): process.returncode for process in self.processes}
        self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state-root', required=True, type=Path)
    parser.add_argument('--resume-state', type=Path, help='Continue the audited private checkpoint without regenerating identities')
    parser.add_argument('--finish-only', action='store_true', help='Validate only re-entry to the retained finished league')
    parser.add_argument('--driver', type=Path, default=TARGET / 'debug/examples/acceptance-driver')
    parser.add_argument('--paper', type=Path, default=TARGET / 'paper-26.3-209.jar')
    default_java = str(Path(os.environ['JAVA_HOME']) / 'bin/java') if os.environ.get('JAVA_HOME') else shutil.which('java')
    parser.add_argument('--java', type=Path, default=default_java)
    args = parser.parse_args()
    if args.finish_only and args.resume_state is None:
        parser.error('--finish-only requires the retained --resume-state')
    args.driver = args.driver.resolve(strict=True)
    args.paper = args.paper.resolve()
    if args.java is None:
        parser.error('Specify --java or JAVA_HOME')
    args.java = args.java.resolve(strict=True)
    os.umask(0o077)
    acceptance = Acceptance(args)
    try:
        acceptance.execute()
    except Exception as error:
        acceptance.result['failure'] = str(error)
        identity_log = acceptance.state / 'identity.jsonl'
        records = [json.loads(line) for line in identity_log.read_text().splitlines()] if identity_log.exists() else []
        pending = json.loads(acceptance.pending_record.read_text()) if acceptance.pending_record else None
        acceptance.result['failure_context'] = {
            'phase': acceptance.phase, 'host_poll_before_cleanup': acceptance.host.poll() if acceptance.host else None,
            'host_started': acceptance.host is not None,
            'identity_sequence': records[-1]['sequence'] if records else 0,
            'pending_record_path': str(acceptance.pending_record) if acceptance.pending_record else None,
            'pending_record_action': pending['action'] if pending else None,
            'pending_exact_record_committed': pending in records if pending else None}
        acceptance.save()
        raise
    finally:
        acceptance.close()


if __name__ == '__main__':
    main()
