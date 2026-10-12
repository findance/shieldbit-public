"""Extra installed-artifact authorization checks; no wallet/state persistence."""
import argparse
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys


def run(manifest):
    import shieldbit
    from shieldbit.consensus.params import MIN_FEE
    from shieldbit.consensus.validation import validate_transaction
    from shieldbit.core.transaction import Transaction, TxInput, TxOutput, TxType
    from shieldbit.crypto.address import pubkey_to_address, address_to_commitment
    from shieldbit.crypto.hashing import address_commitment, double_sha3
    from shieldbit.crypto.keys import generate_keypair, serialize_public_key, sign
    from shieldbit.network_profile import MAIN, PRIVATE
    package = Path(shieldbit.__file__).resolve().parent
    if not package.is_relative_to(Path(sys.prefix).resolve()):
        raise ValueError('installed wheel in a fresh venv required')
    hashes = {'shieldbit/' + str(p.relative_to(package)): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in sorted(package.rglob('*.py'))}
    if hashes != manifest['source_hashes']:
        raise ValueError('installed source mismatch')
    private, raw = generate_keypair()
    public = serialize_public_key(raw)
    owner = address_commitment(public)
    point = (b'a' * 32, 0)
    amounts, owners = {point: 10000}, {point: owner}
    tx = Transaction(TxType.TRANSFER, (TxInput(*point, public_key=public),), (TxOutput(9000, owner),))
    tx = replace(tx, inputs=(replace(tx.inputs[0], signature=sign(private, tx.signing_hash_for(MAIN.network_id))),))
    validate_transaction(tx, amounts, MIN_FEE, utxo_recipients=owners, network_id=MAIN.network_id)
    checks = ['installed_source_fingerprints_match', 'valid_main_domain_payment']
    def rejects(name, action):
        try:
            action()
        except ValueError:
            checks.append(name)
        else:
            raise AssertionError(name + ' was accepted')
    rejects('identical_utxo_cross_network_replay_rejected', lambda: validate_transaction(
        tx, amounts, MIN_FEE, utxo_recipients=owners, network_id=PRIVATE.network_id))
    old = replace(tx, inputs=(replace(tx.inputs[0], signature=sign(private, double_sha3(tx._serialize_for_signing()))),))
    rejects('old_unbound_signature_rejected', lambda: validate_transaction(
        old, amounts, MIN_FEE, utxo_recipients=owners, network_id=MAIN.network_id))
    rejects('wire_version_downgrade_rejected', lambda: validate_transaction(
        replace(tx, version=1), amounts, MIN_FEE, utxo_recipients=owners, network_id=MAIN.network_id))
    assert address_to_commitment(pubkey_to_address(public), 1, expected_commitment_version=2) == owner
    checks.append('full_32_byte_address_roundtrip')
    rejects('legacy_payment_address_rejected', lambda: address_to_commitment(
        pubkey_to_address(public, commitment_version=1), 1, expected_commitment_version=2))
    return {'status': 'passed', 'source_commit': manifest['source_commit'], 'checks': checks,
            'scope': 'installed package, synthetic in-memory UTXOs; not genesis approval',
            'mainnet_launch_authorized': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate-manifest', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    result = run(json.loads(args.candidate_manifest.read_text()))
    with args.report.open('x') as output:
        output.write(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
