"""Headless protocol-777 client for real Paper movement and block interactions.

Packet order and codecs were checked against the pinned Paper 26.3 server classes.
The server supplies the clock and all plugin events; this client sends game packets only.
"""
import hashlib
import hmac
import math
import struct
import threading
import time
import uuid

from minecraft_login import Client, varint, text

PROTOCOL = 777
TICK_SECONDS = 0.1
ACTION_SECONDS = 1.0
BLOCK_Y = 64
PLATFORM_Y = BLOCK_Y - 1


class ActivityClient:
    def __init__(self, address, profile, active, forwarding_key=None):
        self.profile = profile
        self.active = active
        self.client = Client(address)
        self.lock = threading.Lock()
        self.stopping = threading.Event()
        self.positioned = threading.Event()
        self.error = None
        self.position = (0.5, float(BLOCK_Y), 0.5, 0.0, 0.0)
        self.teleports = 0
        self.moves = 0
        self.interactions = 0
        self.sequence = 0
        self.started_ms = int(time.time() * 1000)
        self.client.send(b'\0' + varint(PROTOCOL) + text('localhost')
                         + struct.pack('>H', address[1]) + b'\2')
        self.client.send(b'\0' + text(profile['name']) + uuid.UUID(profile['id']).bytes)
        while True:
            packet_id, fields = self.client.packet()
            if packet_id == 3:
                self.client.compression = fields.integer()
            elif packet_id == 4 and forwarding_key is not None:
                transaction = fields.integer()
                if fields.blob().decode() != 'velocity:player_info':
                    raise ValueError('Unexpected direct-backend forwarding query')
                payload = (varint(1) + text('127.0.0.1') + uuid.UUID(profile['id']).bytes
                           + text(profile['name']) + varint(0))
                signature = hmac.digest(forwarding_key, payload, hashlib.sha256)
                self.client.send(b'\2' + varint(transaction) + b'\1' + signature + payload)
            elif packet_id == 2:
                if uuid.UUID(bytes=fields.take(16)).hex != profile['id']:
                    raise ValueError('Paper changed the authenticated profile')
                if fields.blob().decode() != profile['name']:
                    raise ValueError('Paper changed the player name')
                break
            else:
                raise ValueError('Unexpected login packet: ' + str(packet_id))
        self.client.send(b'\3')
        # Locale, view distance, chat, colors, skin parts, main hand, filtering, listing, particles.
        self.client.send(b'\0' + text('en_us') + b'\2\0\1\0\1\0\1\2')
        while True:
            packet_id, fields = self.client.packet()
            if packet_id == 3:
                self.client.send(b'\3')
                break
            if packet_id == 15:
                self.client.send(b'\7\0')
            elif packet_id in (4, 5):
                self.client.send(varint(packet_id) + fields.take(len(fields.data) - fields.offset))
            elif packet_id == 0:
                self.client.send(b'\1' + fields.take(len(fields.data) - fields.offset) + b'\0')
            elif packet_id == 2:
                raise ValueError('Paper rejected configuration')
            elif packet_id == 20:
                self.client.send(b'\11')
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()
        if not self.positioned.wait(30):
            raise RuntimeError(self.error or 'Paper did not position the player')
        self.sender = threading.Thread(target=self._tick, daemon=True)
        self.sender.start()

    def send(self, packet_id, payload=b''):
        with self.lock:
            self.client.send(varint(packet_id) + payload)

    def _read(self):
        try:
            while not self.stopping.is_set():
                packet_id, fields = self.client.packet()
                if packet_id == 45:  # ClientboundKeepAlivePacket
                    self.send(28, fields.take(8))
                elif packet_id == 62:  # ClientboundPingPacket
                    self.send(45, fields.take(4))
                elif packet_id == 11:  # ClientboundChunkBatchFinishedPacket
                    self.send(11, struct.pack('>f', 8.0))
                elif packet_id == 73:  # ClientboundPlayerPositionPacket
                    teleport = fields.integer()
                    x, y, z, _, _, _, yaw, pitch = struct.unpack('>6d2f', fields.take(56))
                    flags = struct.unpack('>I', fields.take(4))[0]
                    old = self.position
                    self.position = (x + old[0] if flags & 1 else x,
                                     y + old[1] if flags & 2 else y,
                                     z + old[2] if flags & 4 else z,
                                     yaw + old[3] if flags & 8 else yaw,
                                     pitch + old[4] if flags & 16 else pitch)
                    # Protocol 777 acknowledges the resulting coordinates and rotation.
                    self.send(0, varint(teleport) + struct.pack('>3d2f', *self.position))
                    if self.teleports == 0:
                        self.send(44)  # ServerboundPlayerLoadedPacket
                    self.teleports += 1
                    self.positioned.set()
                elif packet_id == 32:
                    raise RuntimeError('Paper disconnect: ' + repr(fields.data[fields.offset:])[:1000])
        except Exception as error:
            if not self.stopping.is_set():
                self.error = str(error)
                self.stopping.set()

    def _tick(self):
        step = 0
        next_action = time.monotonic()
        try:
            while not self.stopping.wait(TICK_SECONDS):
                if self.active and time.monotonic() >= next_action:
                    # A small square around the lever: real movement, distinct blocks and look changes.
                    path = [(0.5, 0.5), (1.5, 0.5), (2.5, 0.5), (2.5, 1.5),
                            (2.5, 2.5), (1.5, 2.5), (0.5, 2.5), (0.5, 1.5)]
                    x, z = path[step % len(path)]
                    yaw = math.degrees(math.atan2(-(0.5 - x), 2.5 - z))
                    self.position = (x, float(BLOCK_Y), z, yaw, 30.0)
                    self.send(31, struct.pack('>3d2fB', *self.position, 1))
                    self.moves += 1
                    self.sequence += 1
                    # Main hand, block (0,64,2), up face, relative hit, inside/border, sequence.
                    block = ((2 & 0x3FFFFFF) << 12) | BLOCK_Y
                    self.send(66, b'\0' + struct.pack('>Q', block) + b'\1'
                              + struct.pack('>3f', 0.5, 0.5, 0.5) + b'\0\0'
                              + varint(self.sequence))
                    self.interactions += 1
                    step += 1
                    next_action = time.monotonic() + ACTION_SECONDS
                self.send(13)  # Every client tick ends here, including idle ticks.
        except Exception as error:
            if not self.stopping.is_set():
                self.error = str(error)
                self.stopping.set()

    def check(self):
        if self.error:
            raise RuntimeError(self.profile['name'] + ': ' + self.error)

    def close(self):
        self.stopping.set()
        self.client.close()
        for thread in [self.reader, self.sender]:
            thread.join(timeout=2)

    def evidence(self):
        return {'profile': self.profile['id'], 'name': self.profile['name'],
                'active': self.active, 'started_ms': self.started_ms,
                'movement_packets': self.moves, 'interaction_packets': self.interactions,
                'teleports': self.teleports, 'error': self.error}
