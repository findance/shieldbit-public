# Copyright 2026 Vipul Tomar (findance) — Apache-2.0
"""
Block and transaction validation rules for ShieldBit.

All validation functions raise ValueError with a descriptive message on failure.
Author: Vipul Tomar
"""
from __future__ import annotations

import time
from typing import TYPE_CHECKING

from shieldbit.consensus.params import (
    MAX_SUPPLY, MIN_FEE, DUST_LIMIT, MAX_BLOCK_SIZE,
    COINBASE_MATURITY, block_reward, MAX_TARGET, GENESIS_BITS,
    RETARGET_INTERVAL, compact_to_target, target_to_compact,
)
from shieldbit.core.transaction import Transaction, TxType
from shieldbit.crypto.hashing import address_commitment
from shieldbit.crypto.keys import verify
from shieldbit.network_profile import network_value

if TYPE_CHECKING:
    from shieldbit.core.block import Block, BlockHeader


# ---------------------------------------------------------------------------
# Transaction validation
# ---------------------------------------------------------------------------

def validate_transaction(
    tx: Transaction,
    available: dict[tuple[bytes, int], int],
    fee: int,
    current_height: int = 0,
    coinbase_maturities: dict[tuple[bytes, int], int] | None = None,
    utxo_recipients: dict[tuple[bytes, int], bytes] | None = None,
    current_time: int | None = None,
    network_id: bytes | None = None,
) -> None:
    """Validate a single transaction against the current UTXO set.

    Args:
        tx: The transaction to validate.
        available: Mapping of (txid, output_index) -> amount for spendable UTXOs.
        fee: Required minimum fee in quanta (0 for coinbase).
        current_height: Current chain height, used for coinbase maturity checks.
        coinbase_maturities: Optional mapping of UTXO outpoint -> creation height
            for coinbase maturity enforcement.
        utxo_recipients: UTXO recipient hashes, required to authorize spending.

    Raises:
        ValueError: On any validation failure.
    """
    # Output amount range checks
    if tx.version != 2:
        raise ValueError("unsupported transaction version")
    if tx.tx_type not in (TxType.TRANSFER, TxType.COINBASE):
        raise ValueError("unsupported transaction type: ordinary payments and coinbase only")
    if len(tx.serialize()) > MAX_BLOCK_SIZE:
        raise ValueError("transaction exceeds maximum block size")
    for output in tx.outputs:
        if not 0 <= output.amount <= MAX_SUPPLY:
            raise ValueError(f"output amount {output.amount} out of range [0, {MAX_SUPPLY}]")
        # Late coinbase subsidies legitimately shrink below payment dust policy.
        if tx.tx_type != TxType.COINBASE and output.amount > 0 and output.amount < DUST_LIMIT:
            raise ValueError(f"output amount {output.amount} below dust limit {DUST_LIMIT}")
        if len(output.recipient) != 32 or output.ephemeral_pubkey:
            raise ValueError("unsupported output recipient or reserved extension format")
    if tx.output_total() > MAX_SUPPLY:
        raise ValueError("aggregate outputs exceed maximum supply")

    # Coinbase transactions have special rules
    if tx.tx_type == TxType.COINBASE:
        _validate_coinbase(tx)
        return

    if not tx.inputs:
        raise ValueError("non-coinbase transaction must have at least one input")
    if not tx.outputs:
        raise ValueError("transaction must have at least one output")
    if tx.lock_height and tx.lock_height > current_height:
        raise ValueError("transaction height lock is not satisfied")
    if tx.lock_time and (current_time is None or tx.lock_time > current_time):
        raise ValueError("transaction time lock is not satisfied")

    # Check for duplicate inputs within this transaction
    points = tx.spent_outpoints()
    if len(points) != len(tx.inputs):
        raise ValueError("transaction contains duplicate inputs")

    # All inputs must reference existing UTXOs
    missing = [p for p in points if p not in available]
    if missing:
        raise ValueError(f"transaction references {len(missing)} missing UTXO(s)")

    # Coinbase maturity: coinbase outputs must be >= COINBASE_MATURITY blocks old
    if coinbase_maturities:
        for point in points:
            created_at = coinbase_maturities.get(point)
            if created_at is not None:
                if current_height - created_at < COINBASE_MATURITY:
                    raise ValueError(
                        f"coinbase output {point} immature: "
                        f"created at {created_at}, current height {current_height}, "
                        f"maturity requires {COINBASE_MATURITY} blocks"
                    )

    input_total = sum(available[p] for p in points)
    if input_total > MAX_SUPPLY:
        raise ValueError("aggregate inputs exceed maximum supply")
    output_total = tx.output_total()

    if output_total > input_total:
        raise ValueError(
            f"outputs ({output_total}) exceed inputs ({input_total})"
        )

    actual_fee = input_total - output_total
    if actual_fee < fee:
        raise ValueError(f"fee {actual_fee} below required {fee}")
    if fee > 0 and actual_fee < MIN_FEE:
        raise ValueError(f"fee {actual_fee} below minimum relay fee {MIN_FEE}")

    if tx.rbf and not any(inp.signals_rbf for inp in tx.inputs):
        raise ValueError("RBF-flagged transaction must have at least one signaling input")

    # Amounts alone cannot establish spending authority. Unsupported scripts
    # remain unspendable until their separate authorization rules are reviewed.
    if utxo_recipients is None:
        raise ValueError("UTXO recipient metadata is required for signature validation")
    from shieldbit.network_profile import ACTIVE
    digest = tx.signing_hash_for(ACTIVE.get().network_id if network_id is None else network_id)
    for inp in tx.inputs:
        point = (inp.prev_txid, inp.output_index)
        recipient = utxo_recipients.get(point)
        if recipient is None or len(recipient) != 32:
            raise ValueError("missing or unsupported UTXO recipient")
        if address_commitment(inp.public_key) != recipient:
            raise ValueError("input public key does not own the referenced UTXO")
        if not verify(inp.public_key, digest, inp.signature):
            raise ValueError("invalid input signature")


def _validate_coinbase(tx: Transaction) -> None:
    """Validate coinbase-specific structure."""
    if tx.inputs:
        raise ValueError("coinbase transaction must have no inputs")
    if tx.rbf or tx.lock_time or tx.lock_height:
        raise ValueError("coinbase must not have RBF or timelocks")
    if len(tx.outputs) == 0:
        raise ValueError("coinbase transaction must have at least one output")
    # data field must start with 8-byte big-endian block height
    if len(tx.data) < 8:
        raise ValueError("coinbase data must contain at least 8 bytes (block height)")


def validate_coinbase_reward(tx: Transaction, height: int, fees: int = 0) -> None:
    """Validate that coinbase reward does not exceed the allowed amount.

    Args:
        tx: The coinbase transaction.
        height: The block height being validated.

    Raises:
        ValueError: If reward exceeds the allowed block reward.
    """
    if tx.tx_type != TxType.COINBASE:
        raise ValueError("expected coinbase transaction")
    if fees < 0:
        raise ValueError("negative block fees")
    allowed = block_reward(height) + fees
    actual = tx.output_total()
    if actual > allowed:
        raise ValueError(
            f"coinbase reward {actual} exceeds allowed {allowed} at height {height}"
        )


# ---------------------------------------------------------------------------
# Block validation
# ---------------------------------------------------------------------------

def validate_block(
    block: Block,
    prev_header: BlockHeader | None,
    utxo_available: dict[tuple[bytes, int], int],
    chain_height: int,
    median_time: int,
    coinbase_maturities: dict[tuple[bytes, int], int] | None = None,
    utxo_recipients: dict[tuple[bytes, int], bytes] | None = None,
    expected_bits: int | None = None,
    network_id: bytes | None = None,
) -> None:
    """Fully validate a block before adding it to the chain.

    Args:
        block: The block to validate.
        prev_header: The previous block's header (None only for genesis).
        utxo_available: Current spendable UTXO set.
        chain_height: Height this block will be added at.
        median_time: Median time past of the last 11 blocks.
        coinbase_maturities: UTXO coinbase creation heights for maturity checks.
        utxo_recipients: Current UTXO recipient hashes for signature validation.

    Raises:
        ValueError: On any validation failure.
    """
    hdr = block.header
    if chain_height < 0 or ((prev_header is None) != (chain_height == 0)):
        raise ValueError("block height and previous-header context disagree")

    from shieldbit.consensus.pow import validate_pow
    validate_pow(block)
    target = compact_to_target(hdr.bits)
    if not 0 < target <= MAX_TARGET or hdr.target != target:
        raise ValueError("invalid or inconsistent difficulty target")
    if target_to_compact(target) != hdr.bits:
        raise ValueError("noncanonical difficulty bits")
    if expected_bits is None:
        if prev_header is not None and chain_height % RETARGET_INTERVAL == 0:
            raise ValueError("retarget validation requires expected difficulty")
        expected_bits = prev_header.bits if prev_header is not None else network_value('GENESIS_BITS', GENESIS_BITS)
    if hdr.bits != expected_bits:
        raise ValueError("block difficulty does not match required bits")

    # --- Previous block linkage ---
    if prev_header is not None:
        if hdr.prev_hash != prev_header.hash:
            raise ValueError("block prev_hash does not match previous block hash")
    else:
        # Genesis block: prev_hash must be all zeros
        if hdr.prev_hash != b'\x00' * 32:
            raise ValueError("genesis block must have zero prev_hash")

    # --- Timestamp ---
    now = int(time.time())
    if hdr.timestamp <= median_time:
        raise ValueError(
            f"block timestamp {hdr.timestamp} not greater than median time {median_time}"
        )
    if hdr.timestamp > now + 7200:
        raise ValueError(
            f"block timestamp {hdr.timestamp} too far in the future (now={now})"
        )

    # --- Block size ---
    try:
        raw = block.serialize()
    except Exception as exc:
        raise ValueError(f"block serialization failed: {exc}") from exc
    if len(raw) > MAX_BLOCK_SIZE:
        raise ValueError(f"block size {len(raw)} exceeds limit {MAX_BLOCK_SIZE}")

    # --- Transaction list ---
    if not block.transactions:
        raise ValueError("block must contain at least one transaction (coinbase)")
    if block.transactions[0].tx_type != TxType.COINBASE:
        raise ValueError("first transaction must be coinbase")
    for tx in block.transactions[1:]:
        if tx.tx_type == TxType.COINBASE:
            raise ValueError("only the first transaction may be coinbase")

    # --- Merkle root ---
    if not block.validate_merkle():
        raise ValueError("block merkle root does not match transaction hashes")
    from shieldbit.core.filters import build_gcs_filter, filter_hash
    expected_filter = filter_hash(build_gcs_filter([
        out.recipient for tx in block.transactions for out in tx.outputs
    ]))
    if hdr.filter_root != expected_filter:
        raise ValueError("block compact filter root does not match outputs")

    # --- Coinbase reward ---
    reward_tx = block.transactions[0]
    validate_transaction(reward_tx, {}, 0)
    if int.from_bytes(reward_tx.data[:8], "big") != chain_height:
        raise ValueError("coinbase height does not match block height")

    # --- Validate all non-coinbase transactions ---
    # Track UTXOs created within this block for intra-block spending
    block_utxos = dict(utxo_available)
    block_recipients = dict(utxo_recipients or {})
    block_maturities = dict(coinbase_maturities or {})
    txids_in_block: set[bytes] = set()
    total_fees = 0

    for pos, tx in enumerate(block.transactions):
        txid = tx.txid
        if pos == 0:
            # Coinbase already validated above
            for idx, out in enumerate(tx.outputs):
                if (txid, idx) in block_utxos:
                    raise ValueError("coinbase would overwrite existing UTXO")
                block_utxos[(txid, idx)] = out.amount
                block_recipients[(txid, idx)] = out.recipient
                block_maturities[(txid, idx)] = chain_height
            txids_in_block.add(txid)
            continue

        # Prevent duplicate txids within a block
        if txid in txids_in_block:
            raise ValueError(f"duplicate txid in block: {txid.hex()}")
        txids_in_block.add(txid)

        validate_transaction(
            tx, block_utxos, MIN_FEE, chain_height, block_maturities,
            block_recipients, median_time,
            network_id,
        )
        total_fees += tx.fee(block_utxos)

        # Spend inputs, add outputs to intra-block UTXO view
        for point in tx.spent_outpoints():
            del block_utxos[point]
            block_recipients.pop(point, None)
            block_maturities.pop(point, None)
        for idx, out in enumerate(tx.outputs):
            if (txid, idx) in block_utxos:
                raise ValueError("transaction would overwrite existing UTXO")
            block_utxos[(txid, idx)] = out.amount
            block_recipients[(txid, idx)] = out.recipient
    validate_coinbase_reward(reward_tx, chain_height, total_fees)
