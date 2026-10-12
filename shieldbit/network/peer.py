# Copyright 2026 Vipul Tomar (findance) — Apache-2.0
"""
Peer metadata and management for ShieldBit P2P networking.

Author: Vipul Tomar
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class PeerInfo:
    """Metadata about a known or connected peer.

    Attributes:
        host: IP address or hostname.
        port: TCP port (default 9333).
        services: Bitmask of supported services.
        version: Reported protocol version.
        user_agent: Reported user agent string.
        start_height: Reported chain height at connection time.
        last_seen: Unix timestamp of last successful contact.
        ban_score: Accumulated misbehavior score (0-100). >=100 = banned.
        connected: Whether we currently have an active connection.
    """
    host: str
    port: int
    services: int = 0
    version: int = 0
    user_agent: str = ''
    start_height: int = 0
    last_seen: float = field(default_factory=time.time)
    ban_score: int = 0
    connected: bool = False
    failures: int = 0
    retry_after: float = 0

    @property
    def address(self) -> tuple[str, int]:
        return (self.host, self.port)

    @property
    def is_banned(self) -> bool:
        return self.ban_score >= 100

    def touch(self) -> None:
        """Update last_seen to now."""
        self.last_seen = time.time()


class PeerManager:
    """Manages the set of known peers.

    Tracks peers discovered from DNS seeds, ADDR messages, and manual config.
    Maintains ban scores to avoid reconnecting to misbehaving peers.
    """

    MAX_PEERS: int = 1000
    STALE_SECONDS: int = 7 * 24 * 3600  # 7 days

    def __init__(self) -> None:
        self._peers: dict[tuple[str, int], PeerInfo] = {}

    def add_peer(self, host: str, port: int, services: int = 0) -> PeerInfo:
        """Add or update a peer.

        Args:
            host: Peer IP/hostname.
            port: Peer port.
            services: Services bitmask.

        Returns:
            PeerInfo for the peer.
        """
        key = (host, port)
        if key in self._peers:
            peer = self._peers[key]
            peer.services = services
            peer.touch()
            return peer
        if len(self._peers) >= self.MAX_PEERS:
            self._evict_stale()
        if len(self._peers) >= self.MAX_PEERS:
            raise ValueError('peer metadata capacity reached')
        peer = PeerInfo(host=host, port=port, services=services)
        self._peers[key] = peer
        return peer

    def update_peer(self, host: str, port: int, **kwargs) -> None:
        """Update fields on a known peer.

        Args:
            host: Peer IP.
            port: Peer port.
            **kwargs: Any PeerInfo fields to update.
        """
        key = (host, port)
        if key not in self._peers:
            self.add_peer(host, port)
        peer = self._peers[key]
        for k, v in kwargs.items():
            if hasattr(peer, k):
                setattr(peer, k, v)
        peer.touch()

    def mark_connected(self, host: str, port: int) -> None:
        self.update_peer(host, port, connected=True)

    def mark_disconnected(self, host: str, port: int) -> None:
        peer = self._peers.get((host, port))
        if peer is not None:
            peer.connected = False
            self.mark_failed(host, port)

    def mark_failed(self, host: str, port: int) -> None:
        peer = self._peers.get((host, port))
        if peer is not None:
            peer.failures = min(peer.failures + 1, 10)
            peer.retry_after = time.monotonic() + min(3600, 5 * 2 ** (peer.failures - 1))

    def mark_healthy(self, host: str, port: int) -> None:
        peer = self._peers.get((host, port))
        if peer is not None:
            peer.failures = 0
            peer.retry_after = 0

    def add_ban_score(self, host: str, port: int, score: int) -> None:
        """Increase a peer's ban score.

        Args:
            host: Peer IP.
            port: Peer port.
            score: Points to add (reaches 100 = banned).
        """
        self.update_peer(host, port)
        self._peers[(host, port)].ban_score += score

    def get_connectable(self, limit: int = 8) -> list[PeerInfo]:
        """Return peers that can be connected to.

        Args:
            limit: Maximum number of peers to return.

        Returns:
            List of PeerInfo sorted by last_seen (most recent first),
            excluding banned and currently connected peers.
        """
        candidates = [
            p for p in self._peers.values()
            if not p.is_banned and not p.connected and p.retry_after <= time.monotonic()
        ]
        candidates.sort(key=lambda p: p.last_seen, reverse=True)
        return candidates[:limit]

    def get_all(self) -> list[PeerInfo]:
        return list(self._peers.values())

    def to_addr_list(self) -> list[tuple[str, int]]:
        """Return a list of (host, port) for ADDR relay."""
        return [p.address for p in self._peers.values() if not p.is_banned]

    def count_connected(self) -> int:
        return sum(1 for p in self._peers.values() if p.connected)

    def _evict_stale(self) -> None:
        """Remove the oldest disconnected non-banned peers to make room."""
        cutoff = time.time() - self.STALE_SECONDS
        stale = [
            k for k, p in self._peers.items()
            if not p.connected and p.last_seen < cutoff
        ]
        for k in stale:
            del self._peers[k]
        # If still over limit, evict oldest
        if len(self._peers) >= self.MAX_PEERS:
            sorted_peers = sorted(self._peers.items(), key=lambda kv: kv[1].last_seen)
            for k, p in sorted_peers:
                if not p.connected:
                    del self._peers[k]
                    if len(self._peers) < self.MAX_PEERS:
                        break

    def __len__(self) -> int:
        return len(self._peers)
