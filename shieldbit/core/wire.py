# Copyright 2026 Vipul Tomar (findance) — Apache-2.0
"""Bounded readers for canonical protocol payloads."""
from shieldbit.consensus.params import MAX_BLOCK_SIZE


class Reader:
    def __init__(self, data: bytes, offset: int = 0):
        if len(data) > MAX_BLOCK_SIZE or not 0 <= offset <= len(data):
            raise ValueError("invalid payload size or offset")
        self.data = data
        self.offset = offset

    @property
    def remaining(self) -> int:
        return len(self.data) - self.offset

    def take(self, size: int) -> bytes:
        if size < 0 or size > self.remaining:
            raise ValueError("truncated payload")
        start = self.offset
        self.offset += size
        return self.data[start:self.offset]

    def uint(self, size: int, byteorder: str = "big") -> int:
        return int.from_bytes(self.take(size), byteorder)

    def blob(self) -> bytes:
        return self.take(self.uint(4))

    def count(self, minimum_size: int) -> int:
        count = self.uint(4)
        if count > self.remaining // minimum_size:
            raise ValueError("item count exceeds remaining payload")
        return count

    def compact_size(self) -> int:
        first = self.uint(1)
        if first < 253:
            return first
        size, minimum = {253: (2, 253), 254: (4, 65536), 255: (8, 2**32)}[first]
        value = self.uint(size, "little")
        if value < minimum:
            raise ValueError("noncanonical compact size")
        return value

    def finish(self) -> None:
        if self.remaining:
            raise ValueError("trailing payload bytes")
