# Copyright 2026 Vipul Tomar (findance) — Apache-2.0
"""Local-only signed-transaction submission over an owner-only Unix socket."""
import asyncio
import json
import logging
import os
from pathlib import Path
import socket

from shieldbit.consensus.params import MAX_BLOCK_SIZE
from shieldbit.core.blockchain import PrunedHistoryRequired

# Hex-encoded transactions also need bounded JSON/list overhead at maximum size.
MAX_REQUEST = MAX_BLOCK_SIZE * 2 + MAX_BLOCK_SIZE // 8 + 4096


async def request(path, method, **parameters):
    reader, writer = await asyncio.wait_for(asyncio.open_unix_connection(str(path), limit=MAX_REQUEST), 5)
    try:
        payload = json.dumps({'method': method, **parameters}).encode() + b'\n'
        if len(payload) > MAX_REQUEST:
            raise ValueError('local request exceeds size limit')
        writer.write(payload)
        await writer.drain()
        response = json.loads(await asyncio.wait_for(reader.readline(), 10))
        if not isinstance(response, dict) or not response.get('ok'):
            raise ValueError(response.get('error', 'node rejected request') if isinstance(response, dict)
                             else 'invalid node response')
        return response
    finally:
        writer.close()
        await writer.wait_closed()


async def submit_transaction(path, tx):
    response = await request(path, 'submit_transaction', transaction=tx.serialize().hex())
    if response.get('txid') != tx.txid.hex():
        raise ValueError('node acknowledged a different transaction')
    return tx.txid


class LocalRPC:
    def __init__(self, node, path):
        self.node = node
        self.path = Path(path)
        self.server = None
        self.inode = None
        self.active = 0
        self._clients = {}

    async def start(self):
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.bind(str(self.path))
            self.inode = self.path.stat().st_ino
            os.chmod(self.path, 0o600)
            sock.setblocking(False)
            self.server = await asyncio.start_unix_server(self.handle, sock=sock, limit=MAX_REQUEST)
        except BaseException:
            sock.close()
            await self.stop()
            raise

    async def stop(self):
        if self.server:
            self.server.close()
            clients = list(self._clients.items())
            for task, writer in clients:
                writer.close()
                if task is not asyncio.current_task():
                    task.cancel()
            await asyncio.gather(*(task for task, _ in clients
                                   if task is not asyncio.current_task()), return_exceptions=True)
            await self.server.wait_closed()
            self.server = None
        if self.inode is not None:
            try:
                if self.path.stat().st_ino == self.inode:
                    self.path.unlink()
            except FileNotFoundError:
                pass
            self.inode = None

    async def handle(self, reader, writer):
        task = asyncio.current_task()
        self._clients[task] = writer
        try:
            await self._handle(reader, writer)
        finally:
            self._clients.pop(task, None)
            writer.close()

    async def _handle(self, reader, writer):
        self.active += 1
        try:
            if self.active > 32:
                raise ValueError('too many local requests')
            payload = await asyncio.wait_for(reader.readline(), 10)
            if len(payload) > MAX_REQUEST or not payload.endswith(b'\n'):
                raise ValueError('invalid local request size or framing')
            command = json.loads(payload)
            if self.server is None:
                raise ValueError('local node is stopping')
            if not isinstance(command, dict):
                raise ValueError('local request must be an object')
            if command.get('method') == 'status':
                response = {'ok': True, **self.node.info()}
            elif command.get('method') == 'estimate_fee':
                response = {'ok': True, 'quanta_per_kb': self.node.mempool.estimate_fee_rate(
                    command.get('target_blocks', 1)), 'basis': 'local_mempool',
                    'confirmation_guaranteed': False}
            elif command.get('method') == 'submit_transaction':
                encoded = command.get('transaction')
                if not isinstance(encoded, str) or len(encoded) > MAX_BLOCK_SIZE * 2:
                    raise ValueError('invalid transaction encoding')
                txid = await self.node.submit_transaction(bytes.fromhex(encoded))
                response = {'ok': True, 'txid': txid.hex(), 'status': 'accepted_to_mempool'}
            elif command.get('method') in ('block_template', 'aux_block_template'):
                encoded = command.get('recipient')
                if not isinstance(encoded, str) or len(encoded) != 64:
                    raise ValueError('invalid mining recipient')
                auxiliary = command['method'] == 'aux_block_template'
                block = self.node.block_template(bytes.fromhex(encoded), auxiliary=auxiliary)
                if auxiliary:
                    from shieldbit.consensus.auxpow import mining_template
                    response = {'ok': True, 'template': mining_template(block)}
                else:
                    response = {'ok': True, 'block': block.serialize().hex()}
            elif command.get('method') == 'submit_aux_block':
                from shieldbit.consensus.auxpow import complete_template
                from shieldbit.consensus.params import MAX_AUXPOW_SIZE
                proof = command.get('proof')
                if not isinstance(proof, str) or len(proof) > MAX_AUXPOW_SIZE * 2:
                    raise ValueError('invalid auxiliary proof encoding')
                block = complete_template(command.get('template'), bytes.fromhex(proof))
                block_hash = await self.node.submit_block(block.serialize())
                response = {'ok': True, 'hash': block_hash.hex(),
                            'canonical': self.node.blockchain.db.get_height_by_hash(block_hash) is not None}
            elif command.get('method') == 'submit_block':
                encoded = command.get('block')
                if not isinstance(encoded, str) or len(encoded) > MAX_BLOCK_SIZE * 2:
                    raise ValueError('invalid block encoding')
                block_hash = await self.node.submit_block(bytes.fromhex(encoded))
                response = {'ok': True, 'hash': block_hash.hex(),
                            'canonical': self.node.blockchain.db.get_height_by_hash(block_hash) is not None}
            else:
                raise ValueError('unknown local method')
        except asyncio.CancelledError:
            writer.close()
            raise
        except PrunedHistoryRequired as exc:
            response = {'ok': False, 'error': str(exc), 'code': 'history_required', 'height': exc.height}
        except (ValueError, TypeError, asyncio.TimeoutError) as exc:
            response = {'ok': False, 'error': str(exc) or 'local request timed out'}
        except Exception:
            logging.getLogger(__name__).exception('Local node request failed')
            response = {'ok': False, 'error': 'local node request failed'}
        finally:
            self.active -= 1
        try:
            writer.write(json.dumps(response).encode() + b'\n')
            await writer.drain()
        except ConnectionError:
            pass
        finally:
            writer.close()
            await writer.wait_closed()
