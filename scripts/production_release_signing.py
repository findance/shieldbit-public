"""Explicit production software-release signing, separate from network activation."""
import argparse
import getpass
import hashlib
from pathlib import Path
import runpy
import sys

review = runpy.run_path(str(Path(__file__).with_name('release_signing.py')))
canonical = review['canonical']
hex_bytes = review['hex_bytes']
read_json = review['read_json']
write_new = review['write_new']
DOMAIN = 'ShieldBit/ProductionRelease/v1'
KIND = 'shieldbit-production-release/v1'


def schema(manifest, commit, network, genesis, trusted):
    if (manifest.get('kind') != KIND or manifest.get('source_commit') != commit or
            manifest.get('network_id') != network or manifest.get('genesis_hash') != genesis or
            manifest.get('approved_signer_sha3_256') != trusted or
            manifest.get('software_release_approved') is not True or
            manifest.get('mainnet_launch_authorized') is not False):
        raise ValueError('production release identity or approval mismatch')
    if len(commit) != 40:
        raise ValueError('exact source commit required')
    hex_bytes(commit, 20)
    for value in (network, genesis, trusted):
        hex_bytes(value, 32)
    artifacts = manifest.get('artifacts')
    if not isinstance(artifacts, dict) or not 1 <= len(artifacts) <= 100:
        raise ValueError('bounded artifact inventory required')
    for name, digest in artifacts.items():
        if not isinstance(name, str):
            raise ValueError('invalid artifact name')
        hex_bytes(digest, 32)


def integrity(manifest, root):
    for name, expected in manifest['artifacts'].items():
        if review['digest_file'](review['artifact_file'](root, name)) != expected:
            raise ValueError('production artifact hash mismatch')


def message(manifest):
    return review['tagged_hash'](DOMAIN, bytes.fromhex(manifest['network_id']) + canonical(manifest))


def envelope(manifest, root, seed, commit, network, genesis, trusted):
    schema(manifest, commit, network, genesis, trusted)
    integrity(manifest, root)
    public = review['public_key_from_seed'](seed)
    if review['fingerprint'](public) != trusted:
        raise ValueError('signer differs from approved fingerprint')
    return {'kind': 'shieldbit-production-release-signature/v1', 'algorithm': 'ML-DSA-65',
            'purpose': DOMAIN, 'key_scope': 'production-release', 'public_key': public.hex(),
            'public_key_sha3_256': trusted,
            'manifest_sha256': hashlib.sha256(canonical(manifest)).hexdigest(),
            'signature': review['sign'](seed, message(manifest)).hex()}


def verify(manifest, signature, root, commit, network, genesis, trusted):
    schema(manifest, commit, network, genesis, trusted)
    if (signature.get('kind') != 'shieldbit-production-release-signature/v1' or
            signature.get('algorithm') != 'ML-DSA-65' or signature.get('purpose') != DOMAIN or
            signature.get('key_scope') != 'production-release'):
        raise ValueError('not a production-release signature')
    public = hex_bytes(signature.get('public_key'), 1953)
    raw = hex_bytes(signature.get('signature'), 3310)
    if review['fingerprint'](public) != trusted or signature.get('public_key_sha3_256') != trusted:
        raise ValueError('production signer trust mismatch')
    if signature.get('manifest_sha256') != hashlib.sha256(canonical(manifest)).hexdigest():
        raise ValueError('production manifest mismatch')
    if not review['verify'](public, message(manifest), raw):
        raise ValueError('invalid production signature')
    integrity(manifest, root)
    return {'signature_valid': True, 'artifact_integrity_valid': True,
            'key_scope': 'production-release', 'mainnet_launch_authorized': False}


def main():
    import json
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['prepare', 'sign', 'verify'])
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--network-id', required=True)
    parser.add_argument('--genesis-hash', required=True)
    parser.add_argument('--trusted-key-sha3-256', required=True)
    parser.add_argument('--signature', type=Path)
    parser.add_argument('--key-file', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--approve-software-release', action='store_true')
    args = parser.parse_args()
    identity = (args.source_commit, args.network_id, args.genesis_hash, args.trusted_key_sha3_256)
    manifest = read_json(args.manifest)
    if args.command == 'prepare':
        if args.signature is None or args.output is None:
            parser.error('prepare needs the original review signature and a new output path')
        review['verify_release'](manifest, read_json(args.signature), args.root,
                                 args.trusted_key_sha3_256, args.network_id, args.source_commit)
        candidate = read_json(args.root / 'candidate.json')
        if candidate['compiled_parameter_snapshot']['profile_identity']['genesis_hash'] != args.genesis_hash:
            raise ValueError('candidate genesis differs from approved pin')
        artifacts = dict(manifest['artifacts'])
        name = args.manifest.resolve().relative_to(args.root.resolve()).as_posix()
        artifacts[name] = review['digest_file'](args.manifest)
        production = {'kind': KIND, 'source_commit': args.source_commit,
                      'network_id': args.network_id, 'genesis_hash': args.genesis_hash,
                      'approved_signer_sha3_256': args.trusted_key_sha3_256,
                      'software_release_approved': True, 'mainnet_launch_authorized': False,
                      'approval_policy': 'effective only with founder production-release signature; not activation approval',
                      'artifacts': artifacts}
        schema(production, *identity)
        write_new(args.output, production)
        print(json.dumps({'production_manifest_prepared': True, 'signature_required': True,
                          'mainnet_launch_authorized': False}))
    elif args.command == 'sign':
        if not args.approve_software_release or not sys.stdin.isatty() or args.key_file is None or args.output is None:
            parser.error('sign requires explicit software-release approval and private interactive key entry')
        schema(manifest, *identity)
        integrity(manifest, args.root)
        seed = review['load_key'](args.key_file, getpass.getpass('Release-key passphrase: '), args.network_id)
        signature = envelope(manifest, args.root, seed, *identity)
        write_new(args.output, signature)
        print(json.dumps({'public_key_sha3_256': args.trusted_key_sha3_256,
                          'key_scope': 'production-release', 'mainnet_launch_authorized': False}))
    else:
        if args.signature is None:
            parser.error('verify requires a signature')
        print(json.dumps(verify(manifest, read_json(args.signature), args.root, *identity)))


if __name__ == '__main__':
    main()
