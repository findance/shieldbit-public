# Copyright 2026 Vipul Tomar (findance) — Apache-2.0
"""
Fee-prioritized transaction mempool for ShieldBit.

Maintains a bounded set of unconfirmed transactions. Supports Replace-By-Fee
for stuck transactions and evicts the lowest-fee transactions when the pool
is full.

Author: Vipul Tomar
"""
from __future__ import annotations

from typing import TYPE_CHECKING
from fractions import Fraction

from shieldbit.consensus.params import MIN_FEE, MAX_BLOCK_SIZE
from shieldbit.consensus.validation import validate_transaction
from shieldbit.core.transaction import Transaction, TxType
from shieldbit.mempool.fees import (
    DEFAULT_RELAY_QUANTA_PER_KB, DEFAULT_INCREMENTAL_QUANTA_PER_KB, required_fee,
)

if TYPE_CHECKING:
    pass

MAX_MEMPOOL_BYTES: int = 50 * 1024 * 1024  # 50 MB


class Mempool:
    """Fee-prioritized unconfirmed transaction pool.

    Attributes:
        transactions: Ordered dict of txid -> Transaction.
    """

    def __init__(self, relay_rate: int = DEFAULT_RELAY_QUANTA_PER_KB,
                 incremental_rate: int = DEFAULT_INCREMENTAL_QUANTA_PER_KB) -> None:
        required_fee(1, relay_rate)
        required_fee(1, incremental_rate)
        self.relay_rate = relay_rate
        self.incremental_rate = incremental_rate
        self.transactions: dict[bytes, Transaction] = {}
        self._fees: dict[bytes, int] = {}
        self._size_bytes: int = 0

    def add(
        self,
        tx: Transaction,
        utxo_available: dict[tuple[bytes, int], int],
        current_height: int = 0,
        utxo_recipients: dict[tuple[bytes, int], bytes] | None = None,
        coinbase_maturities: dict[tuple[bytes, int], int] | None = None,
        current_time: int | None = None,
        network_id: bytes | None = None,
    ) -> None:
        """Validate and add a transaction to the mempool.

        Supports Replace-By-Fee: if the new transaction spends the same inputs
        as an existing one and pays a higher fee, the old tx is evicted.

        Args:
            tx: Transaction to add.
            utxo_available: Current UTXO set (txid, index) -> amount.
            current_height: Current block height for timelock checks.
            utxo_recipients: Recipient hashes required to authorize each input.
            coinbase_maturities: Coinbase creation heights for maturity checks.

        Raises:
            ValueError: If the transaction is invalid or doesn't pay enough fee.
        """
        if tx.tx_type == TxType.COINBASE:
            raise ValueError('coinbase transactions cannot enter the mempool')
        if tx.tx_type != TxType.TRANSFER:
            raise ValueError('unsupported transaction type: ordinary payments only')

        txid = tx.txid

        if txid in self.transactions:
            return  # Already have it

        tx_size = len(tx.serialize())
        fee = self._compute_fee(tx, utxo_available)
        if fee < required_fee(tx_size, self.relay_rate):
            raise ValueError('fee below byte-based relay minimum')

        # Validate before any RBF eviction mutates the pool.
        validate_transaction(
            tx, utxo_available, MIN_FEE, current_height,
            coinbase_maturities, utxo_recipients, current_time,
            network_id,
        )
        if tx.lock_height > 0 and tx.lock_height > current_height:
            raise ValueError(f'transaction locked until height {tx.lock_height}')

        # Check for double-spend / RBF
        input_points = tx.spent_outpoints()
        conflicting_txids: list[bytes] = []
        for existing_txid, existing_tx in self.transactions.items():
            if existing_tx.spent_outpoints() & input_points:
                conflicting_txids.append(existing_txid)

        if conflicting_txids:
            if not any(inp.signals_rbf for inp in tx.inputs):
                raise ValueError(
                    f'transaction conflicts with mempool tx(s) {[t.hex()[:16] for t in conflicting_txids]} '
                    f'and does not signal RBF (sequence must be < 0xFFFFFFFE)'
                )
            # RBF: check that new tx pays higher fee
            new_fee = self._compute_fee(tx, utxo_available)
            old_total_fee = 0
            for ctxid in conflicting_txids:
                old_tx = self.transactions[ctxid]
                if not any(inp.signals_rbf for inp in old_tx.inputs):
                    raise ValueError('original transaction does not permit RBF')
                # Submission's UTXO lookup contains only the new inputs; an
                # original can spend additional outpoints absent from that view.
                old_total_fee += self._fees[ctxid]
            if new_fee <= old_total_fee:
                raise ValueError('RBF fee must exceed the total fees of all replaced transactions')
            if new_fee - old_total_fee < required_fee(tx_size, self.incremental_rate):
                raise ValueError('RBF fee increase must cover replacement bandwidth')
            for ctxid in conflicting_txids:
                old_size = len(self.transactions[ctxid].serialize())
                if new_fee * old_size <= self._fees[ctxid] * tx_size:
                    raise ValueError('RBF must improve the fee rate of every replaced transaction')

        # Stage eviction so a rejected replacement cannot destroy its originals.
        candidates = {tid: existing for tid, existing in self.transactions.items()
                      if tid not in conflicting_txids}
        fees = {tid: self._fees[tid] for tid in candidates}
        candidates[txid] = tx
        fees[txid] = fee
        sizes = {tid: len(existing.serialize()) for tid, existing in candidates.items()}
        size = sum(sizes.values())
        ranked = sorted(candidates, key=lambda tid: (-Fraction(fees[tid], sizes[tid]), tid))
        for tid in reversed(ranked):
            if size <= MAX_MEMPOOL_BYTES:
                break
            size -= sizes[tid]
            del candidates[tid]
            del fees[tid]
        if txid not in candidates:
            raise ValueError('transaction was evicted by mempool capacity policy')
        self.transactions = candidates
        self._fees = fees
        self._size_bytes = size

    def _compute_fee(
        self, tx: Transaction, utxo_available: dict[tuple[bytes, int], int]
    ) -> int:
        """Compute the fee for a transaction.

        Returns 0 if inputs can't be resolved (e.g. mempool chain).
        """
        input_total = 0
        for inp in tx.inputs:
            point = (inp.prev_txid, inp.output_index)
            if point in utxo_available:
                input_total += utxo_available[point]
            else:
                return 0  # Can't calculate fee for unresolved inputs
        return max(0, input_total - tx.output_total())

    def remove(self, txid: bytes) -> None:
        """Remove a transaction from the mempool by txid."""
        tx = self.transactions.pop(txid, None)
        self._fees.pop(txid, None)
        if tx is not None:
            self._size_bytes -= len(tx.serialize())
            if self._size_bytes < 0:
                self._size_bytes = 0

    def revalidate(self, amounts, height, recipients, maturities, current_time, network_id=None) -> None:
        """Drop transactions invalidated by a newly accepted block."""
        for txid, tx in list(self.transactions.items()):
            try:
                validate_transaction(tx, amounts, required_fee(len(tx.serialize()), self.relay_rate),
                                     height, maturities, recipients, current_time, network_id)
                self._fees[txid] = self._compute_fee(tx, amounts)
            except ValueError:
                self.remove(txid)

    def remove_confirmed(self, txids: set[bytes]) -> None:
        """Remove all transactions confirmed in a block.

        Args:
            txids: Set of txids confirmed in the new block.
        """
        for txid in txids:
            self.remove(txid)

    def get_for_block(self, max_bytes: int = MAX_BLOCK_SIZE) -> list[Transaction]:
        """Select the highest actual fee-rate transactions that fit in a block.

        Transactions are sorted by fee per byte (highest first) and included greedily
        until max_bytes is reached.

        Args:
            max_bytes: Maximum total size in bytes (default 6 MB block limit).

        Returns:
            List of transactions for inclusion in the next block.
        """
        candidates = [self.transactions[tid] for tid in self._ranked()]

        selected: list[Transaction] = []
        used_bytes = 0

        for tx in candidates:
            tx_size = len(tx.serialize())
            if used_bytes + tx_size > max_bytes:
                continue
            selected.append(tx)
            used_bytes += tx_size

        return selected

    def contains(self, txid: bytes) -> bool:
        """Return True if txid is in the mempool."""
        return txid in self.transactions

    def get(self, txid: bytes) -> Transaction | None:
        """Return a transaction by txid, or None."""
        return self.transactions.get(txid)

    def all_txids(self) -> list[bytes]:
        """Return all txids currently in the mempool."""
        return list(self.transactions.keys())

    def size_bytes(self) -> int:
        """Return approximate total size in bytes of mempool transactions."""
        return self._size_bytes

    def _evict_lowest_fee(
        self, utxo_available: dict[tuple[bytes, int], int] | None = None
    ) -> None:
        """Remove the lowest actual fee-rate transaction."""
        if not self.transactions:
            return
        worst = self._ranked()[-1]
        self.remove(worst)

    def _ranked(self) -> list[bytes]:
        return sorted(self.transactions, key=lambda tid: (
            -Fraction(self._fees[tid], len(self.transactions[tid].serialize())), tid))

    def estimate_fee_rate(self, target_blocks: int = 1) -> int:
        """Local backlog estimate, not a confirmation promise or historical oracle."""
        if type(target_blocks) is not int or not 1 <= target_blocks <= 1008:
            raise ValueError('target_blocks must be between 1 and 1008')
        # Reserve overhead, including the maximum auxiliary proof, conservatively.
        from shieldbit.consensus.params import MAX_AUXPOW_SIZE
        budget = target_blocks * (MAX_BLOCK_SIZE - MAX_AUXPOW_SIZE - 4096)
        if self._size_bytes <= budget:
            return self.relay_rate
        used = 0
        for tid in self._ranked():
            size = len(self.transactions[tid].serialize())
            used += size
            if used >= budget:
                return max(self.relay_rate, self._fees[tid] * 1000 // size + 1)
        return self.relay_rate

    def __len__(self) -> int:
        return len(self.transactions)

    def __contains__(self, txid: bytes) -> bool:
        return txid in self.transactions
