# Copyright 2026 Vipul Tomar (findance) — Apache-2.0
"""
SQLite persistence layer for ShieldBit blockchain data.

Stores blocks, UTXOs, undo records, compact filters, network settings, and peers.

Author: Vipul Tomar
"""
from __future__ import annotations

import sqlite3
import shutil
from contextlib import contextmanager, closing
from pathlib import Path


class ChainDatabase:
    """Transactional SQLite backend for the ShieldBit chain.

    Args:
        path: Path to the SQLite database file. Defaults to in-memory.
    """

    SCHEMA = """
        CREATE TABLE IF NOT EXISTS chain_settings (
            name TEXT PRIMARY KEY,
            value BLOB NOT NULL
        );
        CREATE TABLE IF NOT EXISTS block_index (
            hash BLOB PRIMARY KEY,
            prev_hash BLOB NOT NULL,
            height INTEGER NOT NULL,
            chainwork TEXT NOT NULL,
            payload BLOB NOT NULL
        );
        CREATE INDEX IF NOT EXISTS block_parent ON block_index(prev_hash);
        CREATE TABLE IF NOT EXISTS block_undo (
            hash BLOB PRIMARY KEY,
            spent BLOB NOT NULL
        );
        CREATE TABLE IF NOT EXISTS blocks (
            height      INTEGER PRIMARY KEY,
            hash        BLOB    UNIQUE NOT NULL,
            prev_hash   BLOB    NOT NULL,
            payload     BLOB    NOT NULL
        );
        CREATE TABLE IF NOT EXISTS utxos (
            txid            BLOB    NOT NULL,
            output_index    INTEGER NOT NULL,
            amount          INTEGER NOT NULL,
            recipient       BLOB    NOT NULL,
            height          INTEGER NOT NULL,
            coinbase        INTEGER NOT NULL,
            PRIMARY KEY (txid, output_index)
        );
        CREATE INDEX IF NOT EXISTS utxos_recipient ON utxos(recipient);
        CREATE TABLE IF NOT EXISTS filters (
            block_hash  BLOB    PRIMARY KEY,
            filter_data BLOB    NOT NULL
        );
        CREATE TABLE IF NOT EXISTS peers (
            address     TEXT    NOT NULL,
            port        INTEGER NOT NULL,
            last_seen   INTEGER NOT NULL DEFAULT 0,
            services    INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (address, port)
        );
    """

    def __init__(self, path: str | Path = ':memory:', max_bytes: int = 4 * 1024 ** 3) -> None:
        if max_bytes <= 0:
            raise ValueError('database budget must be positive')
        self.path = Path(path) if str(path) != ':memory:' else None
        self.connection = sqlite3.connect(str(path), check_same_thread=False)
        self.connection.execute('PRAGMA auto_vacuum=INCREMENTAL')
        self.connection.execute('PRAGMA journal_mode=WAL')
        self.connection.execute('PRAGMA synchronous=FULL')
        page_size = self.connection.execute('PRAGMA page_size').fetchone()[0]
        self.connection.execute(f'PRAGMA max_page_count={max(1, max_bytes // page_size)}')
        self.connection.execute('PRAGMA foreign_keys=ON')
        self.connection.executescript(self.SCHEMA)
        self.connection.commit()
        self._savepoint_number = 0

    def check_disk_space(self, payload_size: int) -> None:
        """Leave room for SQLite pages/WAL; fail without changing canonical state."""
        if self.path is not None:
            free = shutil.disk_usage(self.path.resolve().parent).free
            if free < 100 * 1024 ** 2 + payload_size * 8:
                raise ValueError('chain storage low: free disk space before accepting blocks')

    def get_genesis_commitment(self) -> bytes | None:
        row = self.connection.execute(
            "SELECT value FROM chain_settings WHERE name='genesis'"
        ).fetchone()
        return row[0] if row else None

    def pin_genesis(self, commitment: bytes) -> None:
        existing = self.get_genesis_commitment()
        if len(commitment) != 32 or (existing is not None and existing != commitment):
            raise ValueError('database genesis commitment cannot be changed')
        with self.transaction():
            self.connection.execute(
                "INSERT OR IGNORE INTO chain_settings VALUES ('genesis', ?)", (commitment,)
            )
            if self.get_genesis_commitment() != commitment:
                raise ValueError('database genesis commitment cannot be changed')

    def pin_network(self, identity: bytes, *, allow_legacy: bool) -> None:
        with self.transaction():
            row = self.connection.execute(
                "SELECT value FROM chain_settings WHERE name='network'"
            ).fetchone()
            if row is not None and row[0] != identity:
                raise ValueError('database network profile does not match configured network')
            if row is None and not allow_legacy:
                raise ValueError('refusing untagged existing database; explicit migration required')
            self.connection.execute(
                "INSERT OR IGNORE INTO chain_settings VALUES ('network', ?)", (identity,)
            )

    def trim_side_branches(self, max_blocks: int = 4096, max_bytes: int = 256 * 1024 ** 2) -> None:
        """Remove noncanonical leaves only; never prune canonical history or undo."""
        if max_blocks < 0 or max_bytes < 0:
            raise ValueError('negative side-branch budget')
        with self.transaction():
            self._trim_side_branches(max_blocks, max_bytes)

    def _trim_side_branches(self, max_blocks: int, max_bytes: int) -> None:
        count, size = self.connection.execute(
            'SELECT COUNT(*), COALESCE(SUM(LENGTH(i.payload)), 0) FROM block_index i '
            'LEFT JOIN blocks b ON i.hash=b.hash WHERE b.hash IS NULL'
        ).fetchone()
        while count > max_blocks or size > max_bytes:
            rows = self.connection.execute(
                'SELECT i.hash, LENGTH(i.payload) FROM block_index i LEFT JOIN blocks b ON i.hash=b.hash '
                'WHERE b.hash IS NULL AND NOT EXISTS '
                '(SELECT 1 FROM block_index child WHERE child.prev_hash=i.hash) '
                'ORDER BY i.rowid LIMIT 128'
            ).fetchall()
            if not rows:
                raise ValueError('side-branch retention cannot preserve canonical ancestry')
            # Selected leaves cannot be ancestors of each other or canonical blocks.
            victims = []
            for block_hash, payload_size in rows:
                victims.append((block_hash,))
                count -= 1
                size -= payload_size
                if count <= max_blocks and size <= max_bytes:
                    break
            self.connection.executemany('DELETE FROM block_undo WHERE hash=?', victims)
            self.connection.executemany('DELETE FROM filters WHERE block_hash=?', victims)
            self.connection.executemany('DELETE FROM block_index WHERE hash=?', victims)

    def backup(self, destination: str | Path) -> None:
        """Create an exclusive SQLite-consistent backup, including committed WAL data."""
        import os
        if self.connection.in_transaction:
            raise ValueError('cannot back up an active write transaction')
        destination = Path(destination)
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        try:
            with closing(sqlite3.connect(str(destination))) as target:
                self.connection.backup(target)
                if target.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                    raise ValueError('backup integrity check failed')
            with destination.open('rb') as handle:
                os.fsync(handle.fileno())
            directory_fd = os.open(destination.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except BaseException:
            destination.unlink()
            raise

    @contextmanager
    def transaction(self):
        """Nest writes without allowing a helper to commit its caller's block."""
        self._savepoint_number += 1
        name = f"shieldbit_{self._savepoint_number}"
        self.connection.execute(f"SAVEPOINT {name}")
        try:
            yield
            self.connection.execute(f"RELEASE {name}")
        except BaseException:
            # SQLITE_FULL can automatically roll back every active savepoint.
            if self.connection.in_transaction:
                self.connection.execute(f"ROLLBACK TO {name}")
                self.connection.execute(f"RELEASE {name}")
            raise

    # ------------------------------------------------------------------
    # Blocks
    # ------------------------------------------------------------------

    def save_block(self, height: int, block_hash: bytes, prev_hash: bytes, payload: bytes) -> None:
        with self.transaction():
            self.connection.execute(
                'INSERT INTO blocks VALUES (?, ?, ?, ?)',
                (height, block_hash, prev_hash, payload),
            )

    def get_block_by_height(self, height: int) -> bytes | None:
        row = self.connection.execute(
            'SELECT payload FROM blocks WHERE height=?', (height,)
        ).fetchone()
        from shieldbit.core.block import HEADER_SIZE
        return row[0] if row and len(row[0]) != HEADER_SIZE else None

    def get_header_by_height(self, height: int) -> bytes | None:
        from shieldbit.core.block import HEADER_SIZE
        row = self.connection.execute('SELECT payload FROM blocks WHERE height=?', (height,)).fetchone()
        return row[0][:HEADER_SIZE] if row else None

    def get_setting_int(self, name: str, default: int = 0) -> int:
        row = self.connection.execute('SELECT value FROM chain_settings WHERE name=?', (name,)).fetchone()
        return int(row[0]) if row else default

    def set_setting_int(self, name: str, value: int) -> None:
        self.connection.execute('INSERT OR REPLACE INTO chain_settings VALUES (?, ?)', (name, str(value)))

    def get_block_by_hash(self, block_hash: bytes) -> bytes | None:
        row = self.connection.execute(
            'SELECT payload FROM blocks WHERE hash=?', (block_hash,)
        ).fetchone()
        from shieldbit.core.block import HEADER_SIZE
        if row and len(row[0]) != HEADER_SIZE:
            return row[0]
        record = self.get_indexed_block(block_hash)
        return record[4] if record and len(record[4]) != HEADER_SIZE else None

    def has_block(self, block_hash: bytes) -> bool:
        return self.connection.execute(
            'SELECT 1 FROM blocks WHERE hash=? UNION ALL '
            'SELECT 1 FROM block_index WHERE hash=? LIMIT 1', (block_hash, block_hash)
        ).fetchone() is not None

    def get_indexed_block(self, block_hash: bytes) -> tuple | None:
        return self.connection.execute(
            'SELECT hash, prev_hash, height, chainwork, payload FROM block_index WHERE hash=?',
            (block_hash,),
        ).fetchone()

    def index_block(self, block_hash, prev_hash, height, chainwork, payload) -> None:
        self.connection.execute('INSERT INTO block_index VALUES (?, ?, ?, ?, ?)',
                                (block_hash, prev_hash, height, str(chainwork), payload))

    def save_undo(self, block_hash: bytes, rows: list[tuple]) -> None:
        import json
        encoded = [[r[0].hex(), r[1], r[2], r[3].hex(), r[4], r[5]] for r in rows]
        self.connection.execute('INSERT OR REPLACE INTO block_undo VALUES (?, ?)',
                                (block_hash, json.dumps(encoded)))

    def get_undo(self, block_hash: bytes) -> list[tuple]:
        import json
        row = self.connection.execute('SELECT spent FROM block_undo WHERE hash=?', (block_hash,)).fetchone()
        if row is None:
            raise ValueError('missing block undo data; restore an unpruned chain backup')
        return [(bytes.fromhex(r[0]), r[1], r[2], bytes.fromhex(r[3]), r[4], r[5])
                for r in json.loads(row[0])]

    def height(self) -> int:
        """Return current chain height, or -1 if no blocks."""
        row = self.connection.execute('SELECT COALESCE(MAX(height), -1) FROM blocks').fetchone()
        return row[0]

    def get_height_by_hash(self, block_hash: bytes) -> int | None:
        row = self.connection.execute('SELECT height FROM blocks WHERE hash=?', (block_hash,)).fetchone()
        return row[0] if row else None

    def get_block_hashes(self, from_height: int, to_height: int) -> list[bytes]:
        rows = self.connection.execute(
            'SELECT hash FROM blocks WHERE height BETWEEN ? AND ? ORDER BY height',
            (from_height, to_height),
        ).fetchall()
        return [r[0] for r in rows]

    def prune(self, retain_from: int) -> int:
        """Prune validated bodies/undo, never headers, canonical mappings or UTXOs."""
        from shieldbit.core.block import HEADER_SIZE
        from shieldbit.consensus.params import MIN_PRUNE_BLOCKS
        if type(retain_from) is not int or not 0 <= retain_from <= max(0, self.height() - MIN_PRUNE_BLOCKS + 1):
            raise ValueError('pruning must retain the minimum recent block/undo window')
        floor = self.get_setting_int('prune_height')
        if retain_from <= floor:
            return 0
        with self.transaction():
            missing = self.connection.execute(
                'SELECT 1 FROM blocks b LEFT JOIN block_index i ON b.hash=i.hash '
                'WHERE b.height >= ? AND b.height < ? AND '
                '(i.hash IS NULL OR substr(i.payload,1,?) != substr(b.payload,1,?)) LIMIT 1',
                (floor, retain_from, HEADER_SIZE, HEADER_SIZE),
            ).fetchone()
            if missing:
                raise ValueError('validated fork index is required before pruning')
            count = self.connection.execute(
                'SELECT COUNT(*) FROM blocks WHERE height >= ? AND height < ? AND length(payload)>?',
                (floor, retain_from, HEADER_SIZE),
            ).fetchone()[0]
            self.connection.execute(
                'UPDATE block_index SET payload=substr(payload,1,?) WHERE hash IN '
                '(SELECT hash FROM blocks WHERE height >= ? AND height < ?)', (HEADER_SIZE, floor, retain_from),
            )
            self.connection.execute(
                'DELETE FROM block_undo WHERE hash IN '
                '(SELECT hash FROM blocks WHERE height >= ? AND height < ?)', (floor, retain_from),
            )
            self.connection.execute('UPDATE blocks SET payload=substr(payload,1,?) WHERE height >= ? AND height < ?',
                                    (HEADER_SIZE, floor, retain_from))
            self.set_setting_int('prune_height', retain_from)
            return count

    def reclaim_space(self) -> None:
        """Offline maintenance: reclaim reusable pages, preserving an atomic database."""
        if self.connection.in_transaction:
            raise ValueError('cannot compact during a write transaction')
        if self.path and shutil.disk_usage(self.path.resolve().parent).free < self.path.stat().st_size * 2 + 100 * 1024**2:
            raise ValueError('insufficient temporary disk space for database compaction')
        if self.connection.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()[0]:
            raise ValueError('database is in use; stop other readers before compaction')
        self.connection.execute('VACUUM')
        if self.connection.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()[0]:
            raise ValueError('compaction completed but WAL is busy; retry offline')

    # ------------------------------------------------------------------
    # UTXOs
    # ------------------------------------------------------------------

    def put_utxo(
        self, txid: bytes, index: int, amount: int,
        recipient: bytes, height: int, coinbase: bool,
    ) -> None:
        with self.transaction():
            self.connection.execute(
                'INSERT INTO utxos VALUES (?, ?, ?, ?, ?, ?)',
                (txid, index, amount, recipient, height, int(coinbase)),
            )

    def spend(self, txid: bytes, index: int) -> None:
        """Remove a UTXO from the set (spend it).

        Raises:
            ValueError: If the UTXO does not exist.
        """
        with self.transaction():
            n = self.connection.execute(
                'DELETE FROM utxos WHERE txid=? AND output_index=?', (txid, index)
            ).rowcount
            if n != 1:
                raise ValueError(f'UTXO ({txid.hex()}, {index}) not found')

    def utxos(self, recipient: bytes | None = None) -> list[tuple]:
        """Return UTXOs, optionally filtered by recipient address hash."""
        if recipient is not None:
            rows = self.connection.execute(
                'SELECT txid, output_index, amount, recipient, height, coinbase '
                'FROM utxos WHERE recipient=?',
                (recipient,),
            ).fetchall()
        else:
            rows = self.connection.execute(
                'SELECT txid, output_index, amount, recipient, height, coinbase FROM utxos'
            ).fetchall()
        return rows

    def utxos_for_outpoints(self, points) -> list[tuple]:
        """Primary-key lookups scale with referenced inputs, not total chain UTXOs."""
        rows = []
        for txid, index in set(points):
            row = self.connection.execute(
                'SELECT txid, output_index, amount, recipient, height, coinbase '
                'FROM utxos WHERE txid=? AND output_index=?', (txid, index)
            ).fetchone()
            if row is not None:
                rows.append(row)
        return rows

    # ------------------------------------------------------------------
    # Compact filters
    # ------------------------------------------------------------------

    def save_filter(self, block_hash: bytes, filter_data: bytes) -> None:
        with self.transaction():
            self.connection.execute(
                'INSERT OR REPLACE INTO filters VALUES (?, ?)',
                (block_hash, filter_data),
            )

    def get_filter(self, block_hash: bytes) -> bytes | None:
        row = self.connection.execute(
            'SELECT filter_data FROM filters WHERE block_hash=?', (block_hash,)
        ).fetchone()
        return row[0] if row else None

    # ------------------------------------------------------------------
    # Peers
    # ------------------------------------------------------------------

    def save_peer(self, address: str, port: int, services: int = 0) -> None:
        import time as _time
        with self.transaction():
            self.connection.execute(
                'INSERT OR REPLACE INTO peers VALUES (?, ?, ?, ?)',
                (address, port, int(_time.time()), services),
            )

    def update_peer_seen(self, address: str, port: int) -> None:
        import time as _time
        with self.transaction():
            self.connection.execute(
                'UPDATE peers SET last_seen=? WHERE address=? AND port=?',
                (int(_time.time()), address, port),
            )

    def get_peers(self) -> list[tuple]:
        return self.connection.execute(
            'SELECT address, port, last_seen, services FROM peers ORDER BY last_seen DESC'
        ).fetchall()

    def remove_stale_peers(self, max_age_seconds: int = 86400 * 7) -> int:
        import time as _time
        cutoff = int(_time.time()) - max_age_seconds
        with self.transaction():
            return self.connection.execute(
                'DELETE FROM peers WHERE last_seen < ?', (cutoff,)
            ).rowcount
