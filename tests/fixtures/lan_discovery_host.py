"""Host isolated identity/application services for a real second-device mDNS acceptance.

Build the existing acceptance-driver example first. Private state stays outside the
workspace; public metadata and evidence use the existing federated-server target.
The device operator owns discovery and genesis assertions. This host claims only
startup and shutdown readiness, never a successful second-device result.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

BASE = Path(__file__).resolve().parents[3]
TARGET = BASE / 'federated-server/target'
DRIVER = TARGET / 'debug/examples/acceptance-driver'
STARTUP_SECONDS = 20
STOP_SECONDS = 15


def invoke(*args):
    result = subprocess.run([str(DRIVER), *map(str, args)], text=True,
                            capture_output=True, timeout=STARTUP_SECONDS)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or 'Acceptance driver command failed')
    return result.stdout.strip()


def write_json(path, value):
    with path.open('x') as handle:
        json.dump(value, handle, indent=2)
        handle.write('\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--address', required=True, help='IPv4 address of the real LAN interface')
    parser.add_argument('--listen-address', help='IPv4 listener address, including 0.0.0.0 for all interfaces')
    parser.add_argument('--published-address', action='append', default=[], metavar='LABEL=IPV4',
                        help='Named public connection candidate; repeat for distinct interfaces')
    parser.add_argument('--state-root', required=True, type=Path,
                        help='Existing private state parent outside the workspace')
    parser.add_argument('--label', default='lan-discovery')
    parser.add_argument('--transport-controls', action='store_true',
                        help='Expose separate TCP health and UDP echo controls; neither validates QUIC')
    args = parser.parse_args()
    published = dict(value.split('=', 1) for value in args.published_address) if args.published_address else {'lan': args.address}
    if not published or any(not re.fullmatch('[a-z0-9_-]+', label) for label in published):
        raise ValueError('Use explicit named public IPv4 candidates')
    listen_address = args.listen_address or args.address
    for value in [args.address, listen_address, *published.values()]:
        socket.inet_pton(socket.AF_INET, value)
    if not re.fullmatch('[a-z0-9-]+', args.label):
        raise ValueError('Use a simple output label without directories')
    public_path = TARGET / (args.label + '-public.json')
    result_path = TARGET / (args.label + '-result.json')
    host_log = TARGET / (args.label + '-host.log')
    stop_path = TARGET / (args.label + '-stop')
    os.umask(0o077)
    state_root = args.state_root.resolve(strict=True)
    if state_root.is_relative_to(BASE) or not state_root.is_dir():
        raise ValueError('Private state root must be an existing directory outside the workspace')
    if any(path.exists() for path in (public_path, result_path, host_log, stop_path)):
        raise FileExistsError('LAN acceptance output is already in use; preserve and review it first')
    state = Path(tempfile.mkdtemp(prefix='lan-discovery-', dir=state_root))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        connection.bind((listen_address, 0))
        port = connection.getsockname()[1]
    peer = invoke('keygen', '--out', state / 'host.key')
    if (state / 'host.key').stat().st_mode & 0o077:
        raise ValueError('Fixture identity must be owner-only')
    founder = json.loads(invoke('trust', 'founder', '--member', 'lan-founder',
                               '--club', 'lan-test', '--peer', peer))
    write_json(state / 'identity-genesis.json', {
        'federation': 'isolated-lan-discovery-test', 'quorum': 1, 'founders': [founder]})
    identity_hash = invoke('trust', 'digest', '--genesis', state / 'identity-genesis.json')
    binding = {'genesis': identity_hash, 'namespace': 'application', 'service': 'application',
               'club': 'lan-test', 'audience': peer}
    write_json(state / 'binding.json', binding)
    application_hash = invoke('business-genesis', '--binding', state / 'binding.json',
                              '--out', state / 'application-genesis.json')
    if identity_hash == application_hash:
        raise ValueError('The two independently fetched genesis hashes must differ')
    listen = f'/ip4/{listen_address}/udp/{port}/quic-v1'
    candidates = {label: f'/ip4/{ip}/udp/{port}/quic-v1' for label, ip in published.items()}
    write_json(state / 'host.json', {'node': {
        'key': str(state / 'host.key'), 'listen': [listen], 'external': list(candidates.values()),
        'lan_discovery': True}, 'services': {
            'identity': {'genesis': str(state / 'identity-genesis.json'),
                         'genesis_hash': identity_hash, 'log': str(state / 'identity.jsonl'),
                         'writer': True, 'max_staleness_seconds': 60},
            'governance': {'genesis': str(state / 'application-genesis.json'),
                           'journal': str(state / 'application-journal'), 'binding': binding}}})
    stopped = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stopped.set())
    evidence = {'scope': 'isolated LAN host lifecycle; device assertions recorded separately',
                'state_directory': str(state), 'host_ready': False, 'host_stopped': False,
                'driver_sha256': hashlib.sha256(DRIVER.read_bytes()).hexdigest(),
                'fixture_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    process = None
    controls = []
    udp = None
    http = None
    try:
        with host_log.open('x') as log:
            process = subprocess.Popen([str(DRIVER), 'run', '--config', str(state / 'host.json')],
                                       stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            deadline = time.monotonic() + STARTUP_SECONDS
            status = None
            while time.monotonic() < deadline and not stopped.is_set():
                if process.poll() is not None:
                    raise RuntimeError('Isolated host exited before readiness; see host log')
                for line in host_log.read_text().splitlines():
                    if line.startswith('{'):
                        candidate = json.loads(line)
                        if candidate.get('peer') == peer:
                            status = candidate
                if status is not None:
                    break
                stopped.wait(0.1)
            if status is None or not {'identity', 'application'}.issubset(status['services']):
                raise RuntimeError('Isolated host did not publish identity and application readiness')
            public = {'peer': peer, 'identity_genesis_hash': identity_hash,
                      'application_genesis_hash': application_hash,
                      'address': next(iter(candidates.values())) + '/p2p/' + peer,
                      'published_addresses': {label: address + '/p2p/' + peer for label, address in candidates.items()}}
            if args.transport_controls:
                evidence['control_events'] = []
                udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp.bind((args.address, 0))
                udp.settimeout(0.2)
                public['udp_echo_port'] = udp.getsockname()[1]

                def echo():
                    while not stopped.is_set():
                        try:
                            payload, remote = udp.recvfrom(512)
                            udp.sendto(payload, remote)
                            evidence['control_events'].append({
                                'transport': 'udp_echo', 'remote': remote, 'bytes': len(payload),
                                'unix_ms': time.time_ns() // 1_000_000})
                        except socket.timeout:
                            continue
                        except OSError:
                            return

                class Health(BaseHTTPRequestHandler):
                    def do_GET(self):
                        if self.path != '/health':
                            self.send_error(404)
                            return
                        evidence['control_events'].append({
                            'transport': 'tcp_health', 'remote': self.client_address,
                            'unix_ms': time.time_ns() // 1_000_000})
                        body = json.dumps({'purpose': 'TCP control only; not QUIC validation', **public}).encode()
                        self.send_response(200)
                        self.send_header('Content-Type', 'application/json')
                        self.send_header('Content-Length', str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)

                    def log_message(self, *_):
                        pass

                http = HTTPServer(('0.0.0.0', 0), Health)
                public['tcp_control_port'] = http.server_port
                for callback in (echo, http.serve_forever):
                    thread = threading.Thread(target=callback, daemon=True)
                    thread.start()
                    controls.append(thread)
            write_json(public_path, public)
            evidence.update(host_ready=True, public=public, host_pid=process.pid,
                            listener=listen, announced_addresses=status['addresses'],
                            ready_at_unix_ms=time.time_ns() // 1_000_000)
            print(json.dumps({'host_ready': True, 'public_json': str(public_path), 'pid': process.pid}), flush=True)
            while not stopped.wait(0.2) and not stop_path.exists():
                if process.poll() is not None:
                    raise RuntimeError('Isolated host exited during device acceptance')
    except Exception as error:
        evidence['failure'] = str(error)
        raise
    finally:
        stopped.set()
        if http is not None:
            http.shutdown()
            http.server_close()
        if udp is not None:
            udp.close()
        for thread in controls:
            thread.join(timeout=2)
        if process is not None:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=STOP_SECONDS)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=STOP_SECONDS)
            evidence['host_exit_code'] = process.returncode
            evidence['host_stopped'] = process.returncode == 0
        evidence['finished_at_unix_ms'] = time.time_ns() // 1_000_000
        write_json(result_path, evidence)
        print(json.dumps({'host_stopped': evidence['host_stopped'], 'result': str(result_path)}), flush=True)


if __name__ == '__main__':
    main()
