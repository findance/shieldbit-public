"""Installed-wheel CLI rehearsal on disposable private-profile loopback nodes."""
import argparse
import asyncio
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time


def installed_source(manifest):
    import shieldbit
    package = Path(shieldbit.__file__).resolve().parent
    if not package.is_relative_to(Path(sys.prefix).resolve()):
        raise ValueError('Requires an installed wheel in a fresh venv, not an editable checkout')
    hashes = {'shieldbit/' + str(p.relative_to(package)): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in sorted(package.rglob('*.py'))}
    if hashes != manifest['source_hashes']:
        raise ValueError('Installed package does not match the frozen source fingerprints')
    return package


async def run_case(output, manifest):
    package = installed_source(manifest)
    if os.geteuid() == 0:
        raise ValueError('Installed CLI smoke must run as a non-root operator')
    output = Path(output).resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    from shieldbit.network_profile import ACTIVE, PRIVATE
    from shieldbit.core.block import Block
    from shieldbit.core.blockchain import Blockchain
    from shieldbit.consensus.pow import mine_block
    from shieldbit.crypto.address import address_to_commitment
    from shieldbit.wallet.wallet import Wallet
    from shieldbit.storage.database import ChainDatabase
    from shieldbit.mempool.mempool import Mempool
    from shieldbit.network.node import Node
    from shieldbit.network.local_rpc import request

    token = ACTIVE.set(PRIVATE)
    report = {'status': 'running', 'scope': 'installed-wheel CLI; disposable private-profile loopback only',
              'mainnet_launch_authorized': False, 'source_commit': manifest['source_commit'],
              'package_sha256': manifest['source_hashes'], 'checks': [],
              'python': sys.version.split()[0], 'sqlite': sqlite3.sqlite_version,
              'dependencies': {d.metadata['Name']: d.version for d in importlib.metadata.distributions()},
              'installed_package': str(package)}
    processes, logs, commands = [], [], []
    started = time.monotonic()

    def record(name):
        report['checks'].append(name)

    def stop(index):
        process = processes[index]
        if process.poll() is None:
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
                raise RuntimeError('CLI clean-stop deadline exceeded')
        if process.returncode != 0:
            raise RuntimeError('CLI node exited unsuccessfully')

    with tempfile.TemporaryDirectory(prefix='sb-artifact-', dir='/tmp') as sockets:
        paths = [Path(sockets) / f'{i}.sock' for i in range(3)]
        reservations = [socket.socket() for _ in range(3)]
        for sock in reservations:
            sock.bind(('127.0.0.1', 0))
        ports = [sock.getsockname()[1] for sock in reservations]
        for sock in reservations:
            sock.close()
        try:
            fixture = output / 'fixture'
            fixture.mkdir(mode=0o700)
            wallet = Wallet(str(fixture / 'wallet.json'), 'disposable-artifact-smoke-password')
            owner = address_to_commitment(wallet.create_address())
            recipient_address = wallet.create_address()
            recipient = address_to_commitment(recipient_address)
            genesis = Block.create_genesis(owner)
            oracle_db = ChainDatabase(fixture / 'oracle.db')
            oracle = Blockchain(oracle_db, genesis_hash=genesis.header.hash)
            oracle_node = Node(oracle, Mempool())
            blocks = [genesis]
            await oracle_node.submit_block(genesis.serialize())
            for _ in range(100):
                block = mine_block(oracle_node.block_template(owner), max_nonce=100000)
                if block is None:
                    raise RuntimeError('Disposable fixture nonce search exhausted')
                await oracle_node.submit_block(block.serialize())
                blocks.append(block)
            wallet.blockchain = oracle
            payment = wallet.build_transaction(recipient_address, 1000)
            await oracle_node.submit_transaction(payment.serialize())
            final = mine_block(oracle_node.block_template(owner), max_nonce=100000)
            if final is None:
                raise RuntimeError('Disposable payment fixture nonce search exhausted')
            await oracle_node.submit_block(final.serialize())
            expected_rows = sorted(oracle_db.utxos())
            expected_work = oracle_db.get_indexed_block(final.header.hash)[3]
            oracle_db.connection.close()
            for index in range(3):
                directory = output / f'node-{index}'
                command = [sys.executable, '-I', '-m', 'shieldbit.cli.main',
                           '--network', 'private-testnet', '--data-dir', str(directory),
                           'node', 'start', '--bind', '127.0.0.1', '--port', str(ports[index]),
                           '--node-socket', str(paths[index]), '--genesis-hash', genesis.header.hash.hex(),
                           '--prune', '0' if index == 0 else '288']
                for other in range(3):
                    if other != index:
                        command.extend(['--peer', f'127.0.0.1:{ports[other]}'])
                commands.append(command)
                logs.append((output / f'node-{index}.log').open('ab'))
                processes.append(subprocess.Popen(command, cwd=output, stdout=logs[-1], stderr=subprocess.STDOUT))
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    if processes[index].poll() is not None:
                        raise RuntimeError(f'CLI node {index} failed staged startup')
                    try:
                        await request(paths[index], 'status')
                        break
                    except (OSError, ValueError):
                        await asyncio.sleep(.05)
                else:
                    raise RuntimeError('CLI staged startup deadline exceeded')

            async def statuses():
                states = []
                for index in range(3):
                    if processes[index].poll() is not None:
                        raise RuntimeError(f'CLI node {index} exited; inspect its private log')
                    try:
                        states.append(await request(paths[index], 'status'))
                    except (OSError, ValueError):
                        return None
                return states

            async def wait_for(tip=None):
                deadline = time.monotonic() + 20
                while time.monotonic() < deadline:
                    states = await statuses()
                    if states and (tip is None or all(s['tip'] == tip for s in states)):
                        return states
                    await asyncio.sleep(.05)
                report['failed_convergence'] = {'expected_tip': tip, 'last_statuses': states}
                raise RuntimeError('Installed CLI startup/convergence deadline exceeded')

            await wait_for()
            for path in paths:
                assert path.stat().st_mode & 0o077 == 0
            record('installed_cli_archive_two_pruned_start_and_owner_only_rpc')
            duplicate = subprocess.run(commands[0], cwd=output, capture_output=True, timeout=5)
            assert duplicate.returncode != 0
            record('duplicate_datadir_writer_refused')
            wrong_network = subprocess.run([sys.executable, '-I', '-m', 'shieldbit.cli.main',
                                            '--network', 'main', '--data-dir', str(output / 'node-0'), 'info'],
                                           cwd=output, capture_output=True, timeout=5)
            assert wrong_network.returncode != 0
            record('mixed_main_private_datadir_refused')
            for block in blocks:
                await request(paths[0], 'submit_block', block=block.serialize().hex())
                await wait_for(block.header.hash.hex())
            await request(paths[0], 'submit_transaction', transaction=payment.serialize().hex())
            await request(paths[0], 'submit_block', block=final.serialize().hex())
            states = await wait_for(final.header.hash.hex())
            assert len({s['chainwork'] for s in states}) == 1
            record('real_mldsa_payment_and_cli_peer_convergence')
            stop(2)
            assert not paths[2].exists()
            processes[2] = subprocess.Popen(commands[2], cwd=output, stdout=logs[2], stderr=subprocess.STDOUT)
            await wait_for(final.header.hash.hex())
            record('clean_cli_restart_preserves_pin_tip_and_prune_policy')
            for index in range(3):
                stop(index)
            for index in range(3):
                db = ChainDatabase(output / f'node-{index}' / 'shieldbit.db')
                try:
                    recovered = Blockchain(db)
                    assert recovered.tip == final.header.hash
                    assert sorted(db.utxos()) == expected_rows
                    assert db.get_indexed_block(recovered.tip)[3] == expected_work
                    assert recovered.get_balance(recipient) == 1000
                    assert db.connection.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
                    db.backup(output / f'backup-{index}.db')
                finally:
                    db.connection.close()
                restored = ChainDatabase(output / f'backup-{index}.db')
                try:
                    assert Blockchain(restored).tip == final.header.hash
                    assert sorted(restored.utxos()) == expected_rows
                    assert restored.connection.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
                finally:
                    restored.connection.close()
            record('three_cold_ledgers_and_consistent_backup_restore')
            report['status'] = 'passed'
            report['height'] = states[0]['height']
            report['genesis_scope'] = 'fresh disposable PRIVATE profile; not a proposed production genesis'
        except BaseException as exc:
            report['status'] = 'failed'
            report['error'] = f'{type(exc).__name__}: {exc}'
            raise
        finally:
            for process in processes:
                if process.poll() is None:
                    process.send_signal(signal.SIGINT)
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
            for log in logs:
                log.close()
            ACTIVE.reset(token)
            report['duration_seconds'] = time.monotonic() - started
            path = output / 'deployment-smoke-report.json'
            path.write_text(json.dumps(report, indent=2) + '\n')
            path.chmod(0o600)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--candidate-manifest', type=Path, required=True)
    args = parser.parse_args()
    result = asyncio.run(run_case(args.output_dir, json.loads(args.candidate_manifest.read_text())))
    print(json.dumps({'status': result['status'], 'checks': len(result['checks']),
                      'source_commit': result['source_commit']}))
