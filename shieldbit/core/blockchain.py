# Copyright 2026 Vipul Tomar (findance) — Apache-2.0
"""
Blockchain state manager: ordinary-payment UTXO state and fork recovery.

Wraps ChainDatabase with in-memory caches and full block-application logic
for validated ordinary payments and mining rewards.

Author: Vipul Tomar
"""
from __future__ import annotations

import time
from typing import NamedTuple

from shieldbit.consensus.params import (
    COINBASE_MATURITY, block_reward,
)
from shieldbit.consensus.pow import valid_pow, adjust_target, median_time_past
from shieldbit.core.block import Block, BlockHeader, HEADER_SIZE
from shieldbit.core.transaction import Transaction, TxType
from shieldbit.storage.database import ChainDatabase
from shieldbit.network_profile import ACTIVE, MAIN, network_value


class UTXO(NamedTuple):
    txid: bytes
    output_index: int
    amount: int
    recipient: bytes
    height: int
    coinbase: bool


class PrunedHistoryRequired(ValueError):
    """Missing historical data is a recovery condition, not an invalid fork."""

    def __init__(self, height: int):
        self.height = height
        super().__init__(f'pruned history required at height {height}; recover verified archive history and retry')


class Blockchain:
    """Manages the canonical chain and ordinary-payment UTXO set.

    Attributes:
        db: Persistent SQLite storage backend.
        tip: Hash of the current chain tip block.
    """

    def __init__(self, db: ChainDatabase | None = None, genesis_hash: bytes | None = None,
                 *, prune_depth: int | None = None) -> None:
        if genesis_hash is not None and len(genesis_hash) != 32:
            raise ValueError('genesis commitment must be 32 bytes')
        self.genesis_hash = genesis_hash
        self._profile = ACTIVE.get()
        self._network_id = self._profile.network_id
        self.db: ChainDatabase = db or ChainDatabase()
        persisted = self.db.get_genesis_commitment()
        if persisted is not None:
            if genesis_hash is not None and genesis_hash != persisted:
                raise ValueError('configured genesis differs from persisted commitment')
            genesis_hash = self.genesis_hash = persisted
        self.tip: bytes = b'\x00' * 32
        # Restore tip from DB
        self._restore_tip()
        if ACTIVE.get() != MAIN and genesis_hash is None:
            raise ValueError('private-testnet requires an explicit or persisted genesis commitment')
        if genesis_hash is not None and self.height >= 0:
            root = self.db.get_header_by_height(0)
            if root is None or BlockHeader.from_bytes(root).hash != genesis_hash:
                raise ValueError('database genesis does not match configured network')
        self.last_disconnected: tuple[Block, ...] = ()
        self.last_connected: tuple[Block, ...] = ()
        from shieldbit.consensus.params import MIN_PRUNE_BLOCKS
        self.prune_depth = self.db.get_setting_int('prune_depth') if prune_depth is None else prune_depth
        if type(self.prune_depth) is not int or self.prune_depth < 0:
            raise ValueError('prune depth must be a nonnegative integer')
        if self.prune_depth != 0 and self.prune_depth < MIN_PRUNE_BLOCKS:
            raise ValueError(f'pruning must retain at least {MIN_PRUNE_BLOCKS} blocks')
        if not self.prune_depth and self.db.get_setting_int('prune_height'):
            raise ValueError('restore pruned history before selecting archival mode')
        with self.db.transaction():
            self.db.pin_network(ACTIVE.get().identity(),
                                allow_legacy=self.height < 0)
            if genesis_hash is not None:
                self.db.pin_genesis(genesis_hash)
        if self.prune_depth:
            self._bootstrap_index()
        with self.db.transaction():
            self.db.set_setting_int('prune_depth', self.prune_depth)

    @property
    def network_id(self) -> bytes:
        """Immutable signing domain captured when the ledger is opened."""
        return self._network_id

    @property
    def network_profile(self):
        return self._profile

    def _bootstrap_index(self) -> None:
        """Index old canonical history and reconstruct standard-transfer undo."""
        if self.height < 0 or self.db.get_indexed_block(self.tip):
            return
        view = {}
        work = 0
        previous = b'\0' * 32
        with self.db.transaction():
            for height in range(self.height + 1):
                payload = self.db.get_block_by_height(height)
                if payload is None:
                    raise ValueError('complete unpruned history is required for fork migration')
                block = Block.from_bytes(payload)
                if block.header.prev_hash != previous:
                    raise ValueError('invalid historical linkage during fork migration')
                spent = []
                for tx in block.transactions:
                    txid = tx.txid
                    if tx.tx_type not in (TxType.TRANSFER, TxType.COINBASE):
                        raise ValueError('unsupported transaction history cannot be migrated')
                    for inp in tx.inputs:
                        row = view.pop((inp.prev_txid, inp.output_index), None)
                        if row is None:
                            raise ValueError('historical input cannot be reconstructed for undo')
                        if row[4] != height:
                            spent.append(row)
                    for index, output in enumerate(tx.outputs):
                        view[(txid, index)] = (txid, index, output.amount, output.recipient,
                                                 height, int(tx.is_coinbase()))
                work += self._block_work(block)
                self.db.index_block(block.header.hash, previous, height, work, payload)
                self.db.save_undo(block.header.hash, spent)
                previous = block.header.hash

    @staticmethod
    def _block_work(block: Block) -> int:
        from shieldbit.consensus.params import compact_to_target, MAX_TARGET
        target = compact_to_target(block.header.bits)
        if not 0 < target <= MAX_TARGET or block.header.target != target:
            raise ValueError('invalid target for accumulated work')
        return (1 << 256) // (target + 1)

    def _restore_tip(self) -> None:
        """Restore the chain tip hash from the database."""
        h = self.db.height()
        if h >= 0:
            row = self.db.get_header_by_height(h)
            if row:
                self.tip = BlockHeader.from_bytes(row).hash

    # ------------------------------------------------------------------
    # Read API
    # ------------------------------------------------------------------

    @property
    def height(self) -> int:
        """Current chain height (-1 if empty)."""
        return self.db.height()

    def get_utxos(self, recipient: bytes) -> list[UTXO]:
        """Return all unspent outputs for a given address hash."""
        rows = self.db.utxos(recipient)
        return [UTXO(*row) for row in rows]

    def get_balance(self, recipient: bytes, at_height: int | None = None) -> int:
        """Return spendable balance in quanta for a recipient address hash.

        Coinbase outputs require COINBASE_MATURITY confirmations before spending.
        """
        h = self.height if at_height is None else at_height
        return sum(
            u.amount for u in self.get_utxos(recipient)
            if not u.coinbase or h >= u.height + COINBASE_MATURITY
        )

    def get_spendable_utxos(self, recipient: bytes) -> list[UTXO]:
        """Return UTXOs that are currently spendable (coinbase maturity satisfied)."""
        h = self.height
        return [
            u for u in self.get_utxos(recipient)
            if not u.coinbase or h >= u.height + COINBASE_MATURITY
        ]

    def get_block(self, height: int) -> bytes | None:
        """Return raw serialized block at the given height, or None."""
        return self.db.get_block_by_height(height)

    def get_median_time_past(self) -> int:
        """Return median timestamp of the last 11 blocks."""
        h = self.height
        if h < 0:
            return 0
        timestamps = []
        for i in range(max(0, h - 10), h + 1):
            raw = self.db.get_header_by_height(i)
            if raw:
                timestamps.append(BlockHeader.from_bytes(raw).timestamp)
        return median_time_past(timestamps) if timestamps else 0

    def get_timestamps(self, n: int = 2016) -> list[int]:
        """Return the last N block timestamps for difficulty adjustment."""
        h = self.height
        timestamps = []
        for i in range(max(0, h - n + 1), h + 1):
            raw = self.db.get_header_by_height(i)
            if raw:
                timestamps.append(BlockHeader.from_bytes(raw).timestamp)
        return timestamps

    def get_current_bits(self) -> int:
        """Return the difficulty bits that should apply to the next block."""
        from shieldbit.consensus.params import GENESIS_BITS, RETARGET_INTERVAL
        h = self.height
        if h < 0:
            return network_value('GENESIS_BITS', GENESIS_BITS)
        raw = self.db.get_header_by_height(h)
        if not raw:
            raise ValueError("missing chain tip header")
        header = BlockHeader.from_bytes(raw)
        target_int = header.target
        from shieldbit.consensus.params import target_to_compact
        current_bits = header.bits

        # Check if retarget is due
        if (h + 1) % RETARGET_INTERVAL == 0:
            timestamps = self.get_timestamps(RETARGET_INTERVAL)
            if len(timestamps) != RETARGET_INTERVAL:
                raise ValueError("retarget header history is incomplete")
            new_target = adjust_target(target_int, timestamps)
            return target_to_compact(new_target)
        return current_bits

    # ------------------------------------------------------------------
    # Write API
    # ------------------------------------------------------------------

    def _connect_block(self, block: Block) -> int:
        """Validate and append a block to the chain.

        Args:
            block: The block to add.

        Returns:
            The new chain height after adding the block.

        Raises:
            ValueError: If the block is invalid.
        """
        new_height = self.height + 1

        # Include outputs too so pre-existing outpoint collisions stay detectable.
        points = {p for tx in block.transactions for p in tx.spent_outpoints()}
        for tx in block.transactions:
            txid = tx.txid
            points.update((txid, i) for i in range(len(tx.outputs)))
        available: dict[tuple[bytes, int], int] = {}
        recipients: dict[tuple[bytes, int], bytes] = {}
        coinbase_maturities: dict[tuple[bytes, int], int] = {}
        for row in self.db.utxos_for_outpoints(points):
            txid, idx, amount, recipient, created_h, cb = row
            available[(txid, idx)] = amount
            recipients[(txid, idx)] = recipient
            if cb:
                coinbase_maturities[(txid, idx)] = created_h

        # Get previous header for linkage check
        prev_header: BlockHeader | None = None
        if new_height > 0:
            raw_prev = self.db.get_header_by_height(new_height - 1)
            if raw_prev:
                prev_header = BlockHeader.from_bytes(raw_prev)
            else:
                raise ValueError("missing previous block header")

        # Full validation
        from shieldbit.consensus.validation import validate_block
        validate_block(
            block, prev_header, available, new_height,
            self.get_median_time_past(), coinbase_maturities, recipients,
            expected_bits=self.get_current_bits(),
            network_id=self.network_id,
        )

        # Apply the validated block to the UTXO set.
        self._apply_block(block, new_height)
        return new_height

    def _disconnect_tip(self) -> Block:
        payload = self.db.get_block_by_height(self.height)
        if payload is None:
            raise PrunedHistoryRequired(self.height)
        block = Block.from_bytes(payload)
        spent = self.db.get_undo(block.header.hash)
        for tx in block.transactions:
            self.db.connection.execute('DELETE FROM utxos WHERE txid=?', (tx.txid,))
        for row in spent:
            self.db.put_utxo(*row)
        self.db.connection.execute('DELETE FROM blocks WHERE height=?', (self.height,))
        self.tip = block.header.prev_hash
        return block

    def _switch_to(self, target: bytes) -> tuple[list[Block], list[Block]]:
        path = []
        cursor, alternate = self.tip, target
        while cursor != alternate:
            local = self.db.get_indexed_block(cursor)
            remote = self.db.get_indexed_block(alternate)
            if cursor != b'\0' * 32 and local is None:
                raise ValueError('canonical block index is incomplete')
            if alternate != b'\0' * 32 and remote is None:
                raise ValueError('unknown fork ancestor')
            local_height = local[2] if local else -1
            remote_height = remote[2] if remote else -1
            if local_height >= remote_height:
                cursor = local[1]
            else:
                if len(remote[4]) <= HEADER_SIZE:
                    raise PrunedHistoryRequired(remote_height)
                path.append(Block.from_bytes(remote[4]))
                alternate = remote[1]
        disconnected = []
        while self.tip != cursor:
            disconnected.append(self._disconnect_tip())
        connected = list(reversed(path))
        for candidate in connected:
            self._connect_block(candidate)
        return disconnected, connected

    def add_block(self, block: Block) -> int:
        """Validate on the parent's state; adopt only strictly greater chainwork."""
        from shieldbit.consensus.params import MAX_BLOCK_SIZE
        if (self.genesis_hash is not None and block.header.prev_hash == b'\0' * 32
                and block.header.hash != self.genesis_hash):
            raise ValueError('block genesis does not match configured network')
        # Reject cheap header/commitment failures before touching fork state.
        self._block_work(block)
        from shieldbit.consensus.pow import validate_pow
        validate_pow(block)
        if len(block.serialize()) > MAX_BLOCK_SIZE or not block.validate_merkle():
            raise ValueError('invalid block size or merkle commitment')
        self.db.check_disk_space(len(block.serialize()))
        self._bootstrap_index()
        self.last_disconnected = self.last_connected = ()
        if self.db.get_indexed_block(block.header.hash):
            return self.height
        parent = self.db.get_indexed_block(block.header.prev_hash)
        if self.height >= 0 and parent is None:
            raise ValueError('unknown parent or competing genesis')
        if parent is None and block.header.prev_hash != b'\0' * 32:
            raise ValueError('unknown parent')
        old_tip = self.tip
        old_work = int(self.db.get_indexed_block(old_tip)[3]) if self.height >= 0 else 0
        work = (int(parent[3]) if parent else 0) + self._block_work(block)
        disconnected, connected = [], []
        try:
            with self.db.transaction():
                if work > old_work:
                    disconnected, connected = self._switch_to(block.header.prev_hash)
                    height = self._connect_block(block)
                    connected.append(block)
                else:
                    # Validate a side block against its own ancestor state, then
                    # discard the temporary canonical/UTXO changes atomically.
                    class ValidatedSideBranch(Exception):
                        pass
                    try:
                        with self.db.transaction():
                            self._switch_to(block.header.prev_hash)
                            height = self._connect_block(block)
                            raise ValidatedSideBranch()
                    except ValidatedSideBranch:
                        self.tip = old_tip
                self.db.index_block(block.header.hash, block.header.prev_hash, height, work, block.serialize())
                self.db.trim_side_branches()
                if self.prune_depth and work > old_work:
                    self.db.prune(max(0, self.height - self.prune_depth + 1))
        except BaseException:
            self.tip = old_tip
            raise
        self.last_disconnected = tuple(disconnected)
        self.last_connected = tuple(connected)
        return self.height

    def recover_history(self, archive_directory: str, from_height: int = 0) -> int:
        """Revalidate a canonical archive in staging before restoring any live data.

        Files are named by canonical header hash with a .sbb suffix. No trusted
        UTXO snapshot is accepted. The active chain remains unchanged on failure.
        """
        from pathlib import Path
        from tempfile import TemporaryDirectory
        from shieldbit.consensus.params import MAX_BLOCK_SIZE
        height, tip = self.height, self.tip
        if not isinstance(from_height, int) or not 0 <= from_height <= height:
            raise ValueError('invalid history recovery height')
        directory = Path(archive_directory)
        root = BlockHeader.from_bytes(self.db.get_header_by_height(0)).hash
        with TemporaryDirectory(prefix='shieldbit-recovery-') as temporary:
            staged_db = ChainDatabase(Path(temporary) / 'chain.db')
            try:
                staged = Blockchain(staged_db, genesis_hash=root)
                for index in range(height + 1):
                    expected = self.db.get_header_by_height(index)
                    path = directory / (BlockHeader.from_bytes(expected).hash.hex() + '.sbb')
                    # Read at most one block even for a hostile or changing file.
                    with path.open('rb') as handle:
                        raw = handle.read(MAX_BLOCK_SIZE + 1)
                    if len(raw) > MAX_BLOCK_SIZE or raw[:HEADER_SIZE] != expected:
                        raise ValueError('archive block does not match retained canonical header')
                    staged.add_block(Block.from_bytes(raw))
                from itertools import zip_longest
                query = 'SELECT * FROM utxos ORDER BY txid, output_index'
                if staged.tip != tip or any(a != b for a, b in zip_longest(
                        staged_db.connection.execute(query), self.db.connection.execute(query))):
                    raise ValueError('recovered archive does not reproduce active UTXOs')
                with self.db.transaction():
                    if self.height != height or BlockHeader.from_bytes(self.db.get_header_by_height(height)).hash != tip:
                        raise ValueError('active chain changed during archive recovery')
                    for index in range(from_height, height + 1):
                        raw = staged_db.get_block_by_height(index)
                        block_hash = BlockHeader.from_bytes(raw).hash
                        self.db.connection.execute('UPDATE blocks SET payload=? WHERE height=?', (raw, index))
                        self.db.connection.execute('UPDATE block_index SET payload=? WHERE hash=?', (raw, block_hash))
                        self.db.save_undo(block_hash, staged_db.get_undo(block_hash))
                    self.db.set_setting_int('prune_height', min(from_height, self.db.get_setting_int('prune_height')))
                    if from_height <= self.db.get_setting_int('recovery_height', height + 1):
                        self.db.set_setting_int('recovery_height', -1)
            finally:
                staged_db.connection.close()
        return height - from_height + 1

    def _apply_block(self, block: Block, height: int) -> None:
        """Apply a validated block to the chain state."""
        from shieldbit.core.filters import build_gcs_filter, filter_hash

        with self.db.transaction():
            points = {p for tx in block.transactions for p in tx.spent_outpoints()}
            before = {(r[0], r[1]): r for r in self.db.utxos_for_outpoints(points)}
            spent = [before[p] for tx in block.transactions for p in tx.spent_outpoints() if p in before]
            self.db.save_undo(block.header.hash, spent)
            # Collect all output address hashes for the GCS filter
            filter_items: list[bytes] = []

            for pos, tx in enumerate(block.transactions):
                is_coinbase = pos == 0
                txid = tx.txid

                # Spend inputs (except for coinbase)
                if not is_coinbase:
                    for inp in tx.inputs:
                        self.db.spend(inp.prev_txid, inp.output_index)

                # Create new UTXOs
                for idx, out in enumerate(tx.outputs):
                    self.db.put_utxo(
                        txid, idx, out.amount, out.recipient,
                        height, is_coinbase,
                    )
                    filter_items.append(out.recipient)

            # Build and save compact filter
            gcs = build_gcs_filter(filter_items)
            fhash = filter_hash(gcs)
            self.db.save_block(height, block.header.hash, block.header.prev_hash, block.serialize())
            self.db.save_filter(block.header.hash, gcs)

        self.tip = block.header.hash
