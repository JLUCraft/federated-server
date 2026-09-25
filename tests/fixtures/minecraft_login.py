"""Headless Java 1.20.4 acceptance client for union-authenticated offline hosting.

It does not replace a graphical Minecraft client or implement gameplay.
"""
import socket
import struct
import uuid
import zlib

PROTOCOL = 765
MAX_PACKET = 8 * 1024 * 1024


def varint(value):
    result = bytearray()
    while True:
        part = value & 127
        value >>= 7
        result.append(part | (128 if value else 0))
        if not value:
            return bytes(result)


def text(value):
    encoded = value.encode()
    return varint(len(encoded)) + encoded


class Fields:
    def __init__(self, data):
        self.data = data
        self.offset = 0

    def take(self, length):
        if length < 0 or self.offset + length > len(self.data):
            raise ValueError('truncated packet')
        result = self.data[self.offset:self.offset + length]
        self.offset += length
        return result

    def integer(self):
        value = 0
        for shift in range(0, 35, 7):
            byte = self.take(1)[0]
            value |= (byte & 127) << shift
            if not byte & 128:
                return value
        raise ValueError('invalid varint')

    def blob(self):
        return self.take(self.integer())


class Client:
    def __init__(self, address):
        self.socket = socket.create_connection(address, timeout=30)
        self.compression = None

    def read(self, length):
        result = bytearray()
        while len(result) < length:
            chunk = self.socket.recv(length - len(result))
            if not chunk:
                raise EOFError('Minecraft connection closed')
            result.extend(chunk)
        return bytes(result)

    def packet(self):
        length = 0
        for shift in range(0, 35, 7):
            byte = self.read(1)[0]
            length |= (byte & 127) << shift
            if not byte & 128:
                break
        else:
            raise ValueError('invalid packet length')
        if length > MAX_PACKET:
            raise ValueError('packet too large')
        data = self.read(length)
        if self.compression is not None:
            fields = Fields(data)
            size = fields.integer()
            payload = fields.take(len(data) - fields.offset)
            if size > MAX_PACKET:
                raise ValueError('expanded packet too large')
            data = zlib.decompressobj().decompress(payload, MAX_PACKET + 1) if size else payload
            if size and len(data) != size:
                raise ValueError('compression size mismatch')
        fields = Fields(data)
        packet_id = fields.integer()
        return packet_id, fields

    def send(self, packet):
        if self.compression is not None:
            packet = varint(len(packet)) + zlib.compress(packet) if len(packet) >= self.compression else b'\0' + packet
        data = varint(len(packet)) + packet
        self.socket.sendall(data)

    def close(self):
        self.socket.close()


def login(address, profile):
    client = Client(address)
    try:
        client.send(b'\0' + varint(PROTOCOL) + text('localhost') + struct.pack('>H', address[1]) + b'\2')
        client.send(b'\0' + text(profile['name']) + uuid.UUID(profile['id']).bytes)
        while True:
            packet_id, fields = client.packet()
            if packet_id == 3:
                client.compression = fields.integer()
            elif packet_id == 2:
                authenticated = uuid.UUID(bytes=fields.take(16)).hex
                name = fields.blob().decode()
                break
            elif packet_id == 0:
                raise ValueError('login rejected: ' + fields.blob().decode())
            else:
                raise ValueError('unexpected login packet or online authentication request: ' + str(packet_id))
        client.send(b'\3')
        for _ in range(64):
            packet_id, fields = client.packet()
            if packet_id == 2:
                client.send(b'\2')
                client.packet()
                return {'profile': authenticated, 'name': name, 'phase': 'play'}
            if packet_id == 1:
                raise ValueError('configuration rejected: ' + fields.blob().decode())
            if packet_id in (3, 4):
                client.send(varint(packet_id) + fields.take(len(fields.data) - fields.offset))
        raise ValueError('configuration did not finish')
    finally:
        client.close()
