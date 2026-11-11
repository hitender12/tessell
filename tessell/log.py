"""Tamper-evident append-only build log.

Every published build is recorded as an entry in a hash chain: each entry
commits to the previous entry's hash and to its own payload, so any
modification of history breaks the chain.  Entries are also leaves of a
Merkle tree, so a client can be given a compact inclusion proof that a
particular publish event is in the log without downloading the whole log.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from .store import merkle_proof, merkle_root, sha256_hex, verify_proof


@dataclass(frozen=True)
class LogEntry:
    index: int
    prev_hash: str
    payload: dict
    entry_hash: str


class BuildLog:
    GENESIS_PREV = "0" * 64

    def __init__(self) -> None:
        self.entries: list[LogEntry] = []

    @staticmethod
    def _canonical(payload: dict) -> str:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    def append(self, payload: dict) -> LogEntry:
        prev = self.entries[-1].entry_hash if self.entries else self.GENESIS_PREV
        entry_hash = sha256_hex(f"{prev}:{self._canonical(payload)}".encode("utf-8"))
        entry = LogEntry(len(self.entries), prev, dict(payload), entry_hash)
        self.entries.append(entry)
        return entry

    def verify(self) -> bool:
        """Recompute the whole chain; False if any entry was altered."""
        prev = self.GENESIS_PREV
        for index, entry in enumerate(self.entries):
            if entry.index != index or entry.prev_hash != prev:
                return False
            expected = sha256_hex(
                f"{entry.prev_hash}:{self._canonical(entry.payload)}".encode("utf-8")
            )
            if expected != entry.entry_hash:
                return False
            prev = entry.entry_hash
        return True

    def _tree_entries(self) -> list[tuple[str, str]]:
        return [(str(e.index), e.entry_hash) for e in self.entries]

    def merkle_root(self) -> str:
        return merkle_root(self._tree_entries())

    def inclusion_proof(self, index: int) -> list[tuple[str, bool]]:
        return merkle_proof(self._tree_entries(), str(index))

    def verify_inclusion(self, index: int) -> bool:
        entry = self.entries[index]
        return verify_proof(
            self.merkle_root(),
            str(index),
            entry.entry_hash,
            self.inclusion_proof(index),
        )

    def find_publish(self, package_hash: str, output_hash: str) -> LogEntry | None:
        """The publish entry for a package/output pair, if one is logged."""
        for entry in self.entries:
            payload = entry.payload
            if (
                payload.get("event") == "published"
                and payload.get("package_hash") == package_hash
                and payload.get("output_hash") == output_hash
            ):
                return entry
        return None
