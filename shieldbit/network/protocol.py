# Copyright 2026 Vipul Tomar (findance) — Apache-2.0
"""
ShieldBit P2P network protocol message framing and constructors.

Magic bytes: 0xCCCCCCCC
Checksum: first 4 bytes of double_sha256(payload) — uses SHA-256 for merge-mining compat.

Author: Vipul Tomar
"""
from __future__ import annotations

import struct
import time
from dataclasses import dataclass

from shieldbit.crypto.hashing import double_sha256

from shieldbit.network_profile import network_value

MAGIC: bytes = b'\x53\x48\x42\x54'
PROTOCOL_VERSION: int = 70001

# P2P command constants — 12-byte null-padded ASCII
def _cmd(s: str) -> bytes:
    return s.encode().ljust(12, b'\x00')[:12]

CMD_VERSION:       bytes = _cmd('version')
CMD_VERACK:        bytes = _cmd('verack')
CMD_INV:           bytes = _cmd('inv')
CMD_GETDATA:       bytes = _cmd('getdata')
CMD_NOTFOUND:      bytes = _cmd('notfound')
CMD_BLOCK:         bytes = _cmd('block')
CMD_TX:            bytes = _cmd('tx')
CMD_GETBLOCKS:     bytes = _cmd('getblocks')
CMD_PING:          bytes = _cmd('ping')
CMD_PONG:          bytes = _cmd('pong')
CMD_ADDR:          bytes = _cmd('addr')
# Legacy command identifier is reserved and ignored, not a supported feature.
CMD_CHANNEL_ALERT: bytes = _cmd('channelalert')
CMD_CMPCTBLOCK:    bytes = _cmd('cmpctblock')
CMD_GETBLOCKTXN:   bytes = _cmd('getblocktxn')
CMD_BLOCKTXN:      bytes = _cmd('blocktxn')
CMD_GETCFILTERS:   bytes = _cmd('getcfilters')
CMD_CFILTER:       bytes = _cmd('cfilter')
CMD_REJECT:        bytes = _cmd('reject')

# Inventory type codes
INV_TX:           int = 1
INV_BLOCK:        int = 2
INV_CMPCT_BLOCK:  int = 3
INV_CFILTER:      int = 4

# Header size: magic(4) + command(12) + length(4) + checksum(4) = 24 bytes
HEADER_SIZE: int = 24


@dataclass
class Message:
    """A ShieldBit P2P protocol message.

    Attributes:
        command: 12-byte padded command name.
        payload: Variable-length message body.
    """
    command: bytes
    payload: bytes

    @property
    def checksum(self) -> bytes:
        """Return first 4 bytes of double_sha256(payload)."""
        return double_sha256(self.payload)[:4]

    def to_bytes(self) -> bytes:
        """Serialize to wire format: magic + command + length + checksum + payload."""
        from shieldbit.consensus.params import MAX_BLOCK_SIZE
        if len(self.payload) > MAX_BLOCK_SIZE:
            raise ValueError('message payload exceeds size limit')
        return (
            network_value('MAGIC_BYTES', MAGIC)
            + self.command[:12].ljust(12, b'\x00')
            + struct.pack('<I', len(self.payload))
            + self.checksum
            + self.payload
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> Message | None:
        """Parse a message from wire bytes.

        Args:
            data: Raw bytes starting at message start (including magic).

        Returns:
            Message if valid, None if checksum mismatch or too short.
        """
        if len(data) < HEADER_SIZE:
            return None
        if data[:4] != network_value('MAGIC_BYTES', MAGIC):
            return None
        command = data[4:16]
        length = struct.unpack_from('<I', data, 16)[0]
        from shieldbit.consensus.params import MAX_BLOCK_SIZE
        if length > MAX_BLOCK_SIZE:
            raise ValueError('message payload exceeds size limit')
        checksum = data[20:24]
        if len(data) < HEADER_SIZE + length:
            return None
        payload = data[HEADER_SIZE:HEADER_SIZE + length]
        if double_sha256(payload)[:4] != checksum:
            return None
        return cls(command=command, payload=payload)

    @classmethod
    def read_from_buffer(cls, buf: bytes) -> tuple[Message | None, bytes]:
        """Try to extract one message from a byte buffer.

        Args:
            buf: Accumulated bytes from a socket.

        Returns:
            Tuple of (message_or_None, remaining_bytes).
            If no complete message is present, returns (None, buf).
        """
        if len(buf) < HEADER_SIZE:
            return None, buf
        if buf[:4] != network_value('MAGIC_BYTES', MAGIC):
            raise ValueError('invalid network magic')
        length = struct.unpack_from('<I', buf, 16)[0]
        from shieldbit.consensus.params import MAX_BLOCK_SIZE
        if length > MAX_BLOCK_SIZE:
            raise ValueError('message payload exceeds size limit')
        total = HEADER_SIZE + length
        if len(buf) < total:
            return None, buf
        msg = cls.from_bytes(buf[:total])
        if msg is None:
            raise ValueError('invalid message checksum')
        return msg, buf[total:]


# ---------------------------------------------------------------------------
# Varint encoding (Bitcoin-compatible)
# ---------------------------------------------------------------------------

def _encode_varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    elif n <= 0xFFFF:
        return b'\xfd' + struct.pack('<H', n)
    elif n <= 0xFFFFFFFF:
        return b'\xfe' + struct.pack('<I', n)
    else:
        return b'\xff' + struct.pack('<Q', n)


def _decode_varint(data: bytes, offset: int = 0) -> tuple[int, int]:
    first = data[offset]
    if first < 0xFD:
        return first, offset + 1
    elif first == 0xFD:
        return struct.unpack_from('<H', data, offset + 1)[0], offset + 3
    elif first == 0xFE:
        return struct.unpack_from('<I', data, offset + 1)[0], offset + 5
    else:
        return struct.unpack_from('<Q', data, offset + 1)[0], offset + 9


# ---------------------------------------------------------------------------
# Message constructors
# ---------------------------------------------------------------------------

def version_msg(
    version: int = PROTOCOL_VERSION,
    services: int = 0,
    timestamp: int | None = None,
    height: int = 0,
    user_agent: str = '/ShieldBit:0.1.0/',
    genesis_hash: bytes | None = None,
) -> Message:
    """Build a VERSION handshake message."""
    if timestamp is None:
        timestamp = int(time.time())
    ua_bytes = user_agent.encode()
    payload = (
        struct.pack('<i', version)
        + struct.pack('<Q', services)
        + struct.pack('<q', timestamp)
        + b'\x00' * 26  # addr_recv (simplified)
        + b'\x00' * 26  # addr_from (simplified)
        + struct.pack('<Q', 0)  # nonce
        + _encode_varint(len(ua_bytes))
        + ua_bytes
        + struct.pack('<i', height)
    )
    if genesis_hash is not None:
        if len(genesis_hash) != 32:
            raise ValueError('genesis commitment must be 32 bytes')
        payload += genesis_hash
    return Message(CMD_VERSION, payload)


def verack_msg() -> Message:
    """Build a VERACK acknowledgement message."""
    return Message(CMD_VERACK, b'')


def parse_version(payload: bytes) -> dict:
    """Validate the complete supported VERSION layout before accepting a peer."""
    from shieldbit.core.wire import Reader
    reader = Reader(payload)
    version = int.from_bytes(reader.take(4), 'little', signed=True)
    services = reader.uint(8, 'little')
    reader.take(8 + 26 + 26 + 8)
    size = reader.compact_size()
    if size > 256:
        raise ValueError('peer user agent exceeds size limit')
    try:
        user_agent = reader.take(size).decode('utf-8')
    except UnicodeDecodeError as exc:
        raise ValueError('invalid peer user agent') from exc
    height = int.from_bytes(reader.take(4), 'little', signed=True)
    genesis_hash = reader.take(32) if reader.remaining == 32 else None
    reader.finish()
    if version != PROTOCOL_VERSION or height < -1:
        raise ValueError('unsupported peer protocol or height')
    return {'version': version, 'services': services, 'user_agent': user_agent,
            'start_height': height, 'genesis_hash': genesis_hash}


def ping_msg() -> Message:
    """Build a PING message with a random nonce."""
    import os
    return Message(CMD_PING, os.urandom(8))


def pong_msg(nonce: bytes) -> Message:
    """Build a PONG reply with the given nonce."""
    return Message(CMD_PONG, nonce[:8])


def inv_msg(items: list[tuple[int, bytes]]) -> Message:
    """Build an INV message listing inventory items.

    Args:
        items: List of (type, hash) tuples. type is INV_TX, INV_BLOCK, etc.

    Returns:
        INV Message.
    """
    payload = _encode_varint(len(items))
    for item_type, item_hash in items:
        payload += struct.pack('<I', item_type) + item_hash[:32]
    return Message(CMD_INV, payload)


def getdata_msg(items: list[tuple[int, bytes]]) -> Message:
    """Build a GETDATA message requesting specific items."""
    payload = _encode_varint(len(items))
    for item_type, item_hash in items:
        payload += struct.pack('<I', item_type) + item_hash[:32]
    return Message(CMD_GETDATA, payload)


def tx_msg(tx_bytes: bytes) -> Message:
    """Build a TX message."""
    return Message(CMD_TX, tx_bytes)


def block_msg(block_bytes: bytes) -> Message:
    """Build a BLOCK message."""
    return Message(CMD_BLOCK, block_bytes)


def addr_msg(peers: list[tuple[str, int]]) -> Message:
    """Build an ADDR message sharing known peers.

    Args:
        peers: List of (ip_address_string, port) tuples.

    Returns:
        ADDR Message.
    """
    import socket
    payload = _encode_varint(len(peers))
    for addr, port in peers:
        try:
            ip_bytes = socket.inet_aton(addr)  # IPv4 4 bytes
            # Bitcoin-style addr: timestamp(4) + services(8) + ip(16) + port(2)
            payload += (
                struct.pack('<I', int(time.time()))
                + struct.pack('<Q', 0)  # services
                + b'\x00' * 12 + ip_bytes  # IPv4-mapped IPv6
                + struct.pack('>H', port)
            )
        except OSError:
            continue
    return Message(CMD_ADDR, payload)


def getblocks_msg(known_hash: bytes, stop_hash: bytes = b'\x00' * 32) -> Message:
    """Build a GETBLOCKS message to request block inventory.

    Args:
        known_hash: Hash of the best known block.
        stop_hash: Stop syncing at this hash (zero = sync to tip).
    """
    payload = (
        struct.pack('<I', PROTOCOL_VERSION)
        + _encode_varint(1)
        + known_hash[:32]
        + stop_hash[:32]
    )
    return Message(CMD_GETBLOCKS, payload)


def parse_inv(payload: bytes) -> list[tuple[int, bytes]]:
    """Parse an INV or GETDATA payload.

    Returns:
        List of (type, hash) tuples.
    """
    from shieldbit.core.wire import Reader
    reader = Reader(payload)
    count = reader.compact_size()
    if count > 50_000 or count * 36 != reader.remaining:
        raise ValueError('invalid inventory count or payload length')
    items = []
    for _ in range(count):
        item_type = reader.uint(4, 'little')
        item_hash = reader.take(32)
        items.append((item_type, item_hash))
    return items


def reject_msg(message: str, code: int, reason: str) -> Message:
    """Build a REJECT message."""
    msg_bytes = message.encode()
    reason_bytes = reason.encode()
    payload = (
        _encode_varint(len(msg_bytes)) + msg_bytes
        + bytes([code & 0xFF])
        + _encode_varint(len(reason_bytes)) + reason_bytes
    )
    return Message(CMD_REJECT, payload)
