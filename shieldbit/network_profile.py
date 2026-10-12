# Copyright 2026 Vipul Tomar (findance) - Apache-2.0
"""Explicit, process-command scoped network selection without constant mutation."""
from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass, asdict
import json
import os
from pathlib import Path


@dataclass(frozen=True)
class NetworkProfile:
    name: str
    magic: bytes
    hrp: str
    port: int
    genesis_bits: int
    genesis_timestamp: int
    genesis_message: bytes
    network_id: bytes

    def __post_init__(self):
        if not isinstance(self.network_id, bytes) or len(self.network_id) != 32:
            raise ValueError('signing network identifier must be exactly 32 bytes')

    def identity(self) -> bytes:
        from shieldbit.consensus import params
        data = asdict(self)
        data['magic'] = self.magic.hex()
        data['genesis_message'] = self.genesis_message.hex()
        data['network_id'] = self.network_id.hex()
        if self == MAIN:
            from shieldbit.consensus.genesis import GENESIS_HASH
            data['genesis_hash'] = GENESIS_HASH.hex()
        data['authorization'] = {'address_commitment_version': 2, 'transaction_version': 2,
                                 'signing_format_version': 2,
                                 'signing_tag': 'ShieldBit/TxSignature/v2'}
        data['consensus'] = {name: getattr(params, name) for name in (
            'MAX_SUPPLY', 'INITIAL_REWARD', 'HALVING_INTERVAL', 'COINBASE_MATURITY',
            'MAX_BLOCK_SIZE', 'MAX_TARGET', 'TARGET_BLOCK_SECONDS', 'RETARGET_INTERVAL',
            'MIN_FEE', 'DUST_LIMIT', 'AUXPOW_CHAIN_ID', 'AUXPOW_VERSION')}
        return json.dumps(data, sort_keys=True, separators=(',', ':')).encode('ascii')


MAIN = NetworkProfile('main', b'SHBT', 'sb1', 9333, 0x1e0ffff0,
                      1_791_648_833,
                      b'OM | 0001-01-01T01:01:01Z\nAlways believe future is brighter',
                      bytes.fromhex('3902ef29e80d97be35bdef5c86e71baeadb5ab9dee926040cd56d9c88d268509'))
# Draft private-only parameters, not public-testnet or mainnet approval.
PRIVATE = NetworkProfile('private-testnet', b'SBPT', 'sbt', 19333, 0x1f7fffff,
                         1_791_072_000, b'ShieldBit controlled private testnet; no monetary value',
                         bytes.fromhex('f4187fe80296053b4bd305b297ae13723a1d057083277d0ba7a7d47fd31214aa'))
PROFILES = {profile.name: profile for profile in (MAIN, PRIVATE)}
ACTIVE: ContextVar[NetworkProfile] = ContextVar('shieldbit_network', default=MAIN)


def network_value(name: str, fallback):
    profile = ACTIVE.get()
    if profile == MAIN:
        return fallback
    fields = {'GENESIS_BITS': 'genesis_bits', 'GENESIS_TIMESTAMP': 'genesis_timestamp',
              'GENESIS_MESSAGE': 'genesis_message', 'MAGIC_BYTES': 'magic',
              'ADDRESS_HRP': 'hrp', 'NETWORK_PORT': 'port'}
    return getattr(profile, fields[name])


def bind_data_directory(path: Path, profile: NetworkProfile) -> None:
    if path.is_symlink():
        raise ValueError('data directory must not be a symlink')
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    marker = path / 'network.json'
    identity = profile.identity()
    if not marker.exists() and profile != MAIN and any(path.iterdir()):
        raise ValueError('refusing untagged nonempty private-testnet data directory')
    try:
        descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        descriptor = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, 'rb') as source:
            if source.read(4096) != identity:
                raise ValueError('data directory network profile does not match configured network')
    else:
        with os.fdopen(descriptor, 'wb') as target:
            target.write(identity)
            target.flush()
            os.fsync(target.fileno())
    for name in ('shieldbit.db', 'wallet.json', 'config.json'):
        if (path / name).is_symlink():
            raise ValueError('data files must not be symlinks')
