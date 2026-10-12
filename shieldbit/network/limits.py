# Copyright 2026 Vipul Tomar (findance) — Apache-2.0
"""Local resource policy, not consensus rules."""
from __future__ import annotations

import ipaddress
import time


class TokenBucket:
    def __init__(self, rate: float, capacity: float):
        if rate <= 0 or capacity <= 0:
            raise ValueError('budget must be positive')
        self.rate, self.capacity = rate, capacity
        self.tokens = capacity
        self.updated = time.monotonic()

    def consume(self, amount: float) -> bool:
        if amount < 0:
            raise ValueError('negative budget charge')
        now = time.monotonic()
        self.tokens = min(self.capacity, self.tokens + max(0, now - self.updated) * self.rate)
        self.updated = now
        if amount > self.tokens:
            return False
        self.tokens -= amount
        return True


def network_group(host: str) -> str:
    """Group resolved endpoints; loopback labs still have total connection caps."""
    address = ipaddress.ip_address(host)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    if address.is_loopback:
        return 'loopback'
    prefix = 16 if address.version == 4 else 32
    return str(ipaddress.ip_network(f'{address}/{prefix}', strict=False))
