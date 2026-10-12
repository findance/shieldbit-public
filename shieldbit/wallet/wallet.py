# Copyright 2026 Vipul Tomar (findance) — Apache-2.0
"""
High-level wallet for ShieldBit.

Combines KeyStore (encrypted key storage) with Blockchain (UTXO lookup)
to build, sign, and prepare transactions for broadcast.

Author: Vipul Tomar
"""
from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

from shieldbit.consensus.params import MIN_FEE, QUANTA_PER_SBT, DUST_LIMIT
from shieldbit.core.transaction import Transaction, TxInput, TxOutput, TxType, coinbase
from shieldbit.crypto.address import pubkey_to_address, address_to_commitment
from shieldbit.crypto.keys import (
    generate_keypair, serialize_public_key, public_key_from_seed, sign as _sign,
)
from shieldbit.crypto.shamir import split_secret, recover_secret
from shieldbit.wallet.keystore import KeyStore
from shieldbit.mempool.fees import (
    DEFAULT_RELAY_QUANTA_PER_KB, MLDSA_WIRE_SIGNATURE_BYTES, required_fee,
)

if TYPE_CHECKING:
    from shieldbit.core.blockchain import Blockchain, UTXO


class Wallet:
    """ShieldBit wallet: key management + transaction building.

    Combines an encrypted KeyStore with a live Blockchain reference
    to select UTXOs, build transactions, and sign them.

    Args:
        keystore_path: Path to the encrypted JSON keystore file.
        password: Password for the keystore.
        blockchain: Live Blockchain instance for UTXO lookups.
    """

    def __init__(
        self,
        keystore_path: str,
        password: str,
        blockchain: Blockchain | None = None,
    ) -> None:
        self.ks = KeyStore(keystore_path, password)
        self.blockchain = blockchain

    @classmethod
    def from_keystore(cls, keystore: KeyStore, blockchain: Blockchain) -> Wallet:
        """Reuse an already unlocked keystore without loading secrets again."""
        wallet = cls.__new__(cls)
        wallet.ks = keystore
        wallet.blockchain = blockchain
        return wallet

    # ------------------------------------------------------------------
    # Address management
    # ------------------------------------------------------------------

    def create_address(self, version: int = 1) -> str:
        """Generate a new ML-DSA address and store it in the keystore.

        Args:
            version: Key version (1=ML-DSA-65).

        Returns:
            Bech32m sb1... address string.
        """
        privkey, raw_pubkey = generate_keypair(version)
        pubkey = serialize_public_key(raw_pubkey, version)
        address = pubkey_to_address(pubkey, version)
        addr_hash = address_to_commitment(address)
        self.ks.add_key(privkey, pubkey, version, address, addr_hash)
        return address

    def list_addresses(self) -> list[str]:
        """Return all addresses stored in this wallet."""
        return self.ks.list_addresses()

    def get_first_address(self) -> str | None:
        """Return the first stored address, or None if wallet is empty."""
        addrs = self.ks.list_addresses()
        return addrs[0] if addrs else None

    # ------------------------------------------------------------------
    # Balance queries
    # ------------------------------------------------------------------

    def get_balance(self) -> int:
        """Return total spendable balance in quanta across all addresses.

        Requires a blockchain reference.

        Returns:
            Balance in quanta.
        """
        if self.blockchain is None:
            raise RuntimeError('Wallet has no blockchain reference — cannot query balance')
        total = 0
        for addr in self.ks.list_addresses():
            addr_hash = self.ks.get_address_hash(addr)
            total += self.blockchain.get_balance(addr_hash)
        return total

    def get_balance_sbt(self) -> float:
        """Return total spendable balance in SBT (float)."""
        return self.get_balance() / QUANTA_PER_SBT

    def get_utxos(self) -> list[UTXO]:
        """Return all spendable UTXOs across all wallet addresses."""
        if self.blockchain is None:
            raise RuntimeError('Wallet has no blockchain reference')
        utxos = []
        for addr in self.ks.list_addresses():
            addr_hash = self.ks.get_address_hash(addr)
            utxos.extend(self.blockchain.get_spendable_utxos(addr_hash))
        return utxos

    # ------------------------------------------------------------------
    # Transaction building
    # ------------------------------------------------------------------

    def build_transaction(
        self,
        to_address: str,
        amount: int,
        fee: int | None = None,
        rbf: bool = False,
        from_address: str | None = None,
        fee_rate_per_kb: int = DEFAULT_RELAY_QUANTA_PER_KB,
    ) -> Transaction:
        """Build and sign a payment transaction.

        Selects UTXOs from the wallet, constructs inputs and outputs,
        adds a change output if necessary, and signs with ML-DSA.

        Args:
            to_address: Recipient sb1... address string.
            amount: Amount to send in quanta.
            fee: Optional explicit fee; otherwise estimate the fully signed size.
            rbf: Signal Replace-By-Fee (allows fee bumping later).
            from_address: Optional specific sending address.
            fee_rate_per_kb: Local relay/congestion rate in quanta per 1,000 bytes.

        Returns:
            Fully signed Transaction ready for broadcast.

        Raises:
            ValueError: If balance is insufficient or address is invalid.
        """
        if amount < DUST_LIMIT:
            raise ValueError(f'amount must be at least {DUST_LIMIT} quanta, got {amount}')
        required_fee(1, fee_rate_per_kb)
        if fee is not None and (type(fee) is not int or fee < MIN_FEE):
            raise ValueError(f'fee {fee} below minimum {MIN_FEE}')
        if self.blockchain is None:
            raise RuntimeError('Wallet has no blockchain reference — cannot select UTXOs')
        if self.ks.network_id != self.blockchain.network_id:
            raise ValueError('wallet and blockchain signing networks do not match')

        to_hash = address_to_commitment(to_address, expected_version=1, expected_commitment_version=2)

        # Collect UTXOs
        candidate_addrs = [from_address] if from_address else self.ks.list_addresses()
        selected: list[tuple[str, UTXO]] = []
        total_in = 0
        ready = False
        outputs: list[TxOutput] = []
        unsigned_inputs = ()

        for addr in candidate_addrs:
            if not self.ks.has_address(addr):
                continue
            addr_hash = self.ks.get_address_hash(addr)
            for utxo in self.blockchain.get_spendable_utxos(addr_hash):
                selected.append((addr, utxo))
                total_in += utxo.amount
                unsigned_inputs = tuple(TxInput(
                    prev_txid=item.txid, output_index=item.output_index,
                    public_key=self.ks.get_public_key(owner),
                    sequence=0xFFFFFFFD if rbf else 0xFFFFFFFF,
                ) for owner, item in selected)
                change_hash = self.ks.get_address_hash(selected[0][0])
                outputs = [TxOutput(amount, to_hash), TxOutput(DUST_LIMIT, change_hash)]
                estimate = self.estimate_transaction_fee(unsigned_inputs, tuple(outputs), fee_rate_per_kb)
                budget = estimate if fee is None else fee
                change = total_in - amount - budget
                if change >= DUST_LIMIT:
                    if budget < estimate:
                        raise ValueError(f'explicit fee below signed-size minimum {estimate}')
                    outputs[1] = TxOutput(change, change_hash)
                    ready = True
                else:
                    outputs = [TxOutput(amount, to_hash)]
                    estimate = self.estimate_transaction_fee(unsigned_inputs, tuple(outputs), fee_rate_per_kb)
                    budget = estimate if fee is None else fee
                    if total_in >= amount + budget:
                        if budget < estimate:
                            raise ValueError(f'explicit fee below signed-size minimum {estimate}')
                        ready = True
                if ready:
                    break
            if ready:
                break

        if not ready:
            raise ValueError(
                f'insufficient balance: have {total_in} quanta, '
                f'cannot cover {amount} plus the signed-size fee'
            )

        # Build unsigned tx to get signing hash
        unsigned_tx = Transaction(
            tx_type=TxType.TRANSFER,
            inputs=unsigned_inputs,
            outputs=tuple(outputs),
            rbf=rbf,
        )
        signing_hash = unsigned_tx.signing_hash_for(self.blockchain.network_id)

        # Sign each input
        signed_inputs = []
        for (addr, _utxo), inp in zip(selected, unsigned_inputs):
            privkey = self.ks.get_private_key(addr)
            pubkey = self.ks.get_public_key(addr)
            sig = _sign(privkey, signing_hash, 1)
            signed_inputs.append(replace(inp, signature=sig, public_key=pubkey))

        signed = Transaction(
            tx_type=TxType.TRANSFER,
            inputs=tuple(signed_inputs),
            outputs=tuple(outputs),
            rbf=rbf,
        )
        if total_in - signed.output_total() < required_fee(len(signed.serialize()), fee_rate_per_kb):
            raise ValueError('signed transaction exceeds the estimated fee budget')
        return signed

    @staticmethod
    def estimate_transaction_fee(inputs: tuple[TxInput, ...], outputs: tuple[TxOutput, ...],
                                 rate: int = DEFAULT_RELAY_QUANTA_PER_KB) -> int:
        """ML-DSA signatures have fixed wire size, including their version byte."""
        sized = Transaction(TxType.TRANSFER, tuple(
            replace(inp, signature=b'\0' * MLDSA_WIRE_SIGNATURE_BYTES) for inp in inputs), outputs)
        return required_fee(len(sized.serialize()), rate)

    def sign_transaction(self, tx: Transaction, address: str) -> Transaction:
        """Sign all inputs belonging to `address` in a transaction.

        Useful for multi-input transactions or partially signed transactions.

        Args:
            tx: Transaction with unsigned inputs.
            address: Wallet address whose private key will sign.

        Returns:
            Transaction with signatures filled in for matching inputs.
        """
        privkey = self.ks.get_private_key(address)
        pubkey = self.ks.get_public_key(address)
        signing_hash = tx.signing_hash_for(self.ks.network_id)

        signed_inputs = []
        for inp in tx.inputs:
            if inp.public_key == pubkey:
                sig = _sign(privkey, signing_hash, 1)
                signed_inputs.append(replace(inp, signature=sig))
            else:
                signed_inputs.append(inp)

        return replace(tx, inputs=tuple(signed_inputs))

    async def submit_transaction(self, tx: Transaction, node_socket: str) -> bytes:
        """Submit a signed payment without sharing private keys with the node."""
        from shieldbit.network.local_rpc import submit_transaction
        return await submit_transaction(node_socket, tx)

    # ------------------------------------------------------------------
    # Key recovery
    # ------------------------------------------------------------------

    def setup_recovery(self, address: str, n: int, k: int) -> list[tuple[int, bytes]]:
        """Generate Shamir secret shares for an address's private key.

        Args:
            address: The wallet address to back up.
            n: Total number of shares to generate.
            k: Minimum shares required to reconstruct.

        Returns:
            List of (share_index, share_bytes) tuples.
            Store each share separately — any k shares recover the key.
        """
        privkey = self.ks.get_private_key(address)
        return split_secret(privkey, n, k)

    def restore_recovery(
        self, shares: list[tuple[int, bytes]], expected_address: str, version: int = 1,
    ) -> str:
        """Restore shares only if they reproduce the original wallet address.

        Keep the expected address with the backup: shares alone do not encode
        their threshold or authenticate a reconstructed seed.
        """
        seed = recover_secret(shares)
        public_key = public_key_from_seed(seed, version)
        address = pubkey_to_address(public_key, version)
        if address != expected_address:
            raise ValueError("Recovered seed does not match the expected address")
        self.ks.add_key(seed, public_key, version, address, address_to_commitment(address))
        return address

    @classmethod
    def generate(cls, keystore_path: str, password: str, version: int = 1) -> tuple[Wallet, str]:
        """Create a new wallet with one fresh address.

        Args:
            keystore_path: Path for the keystore file.
            password: Keystore encryption password.
            version: Key version (default 1 = ML-DSA-65).

        Returns:
            Tuple of (Wallet, address_string).
        """
        w = cls(keystore_path, password)
        address = w.create_address(version)
        return w, address
