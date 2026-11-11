"""Content-addressed store and Merkle trees.

Everything in Tessell is named by the SHA-256 of its content: blobs are
stored under their hash, package manifests are Merkle roots over
(path, content-hash) pairs, and the build log is a hash chain whose entries
are leaves of a Merkle tree.  Nothing is trusted because someone *says* it
is correct — it is checked against its hash.
"""

from __future__ import annotations

import hashlib


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class ContentStore:
    """A minimal content-addressed blob store (hash -> bytes)."""

    def __init__(self) -> None:
        self._blobs: dict[str, bytes] = {}

    def put(self, data: bytes) -> str:
        digest = sha256_hex(data)
        self._blobs[digest] = data
        return digest

    def get(self, digest: str) -> bytes | None:
        return self._blobs.get(digest)

    def __contains__(self, digest: str) -> bool:
        return digest in self._blobs

    def __len__(self) -> int:
        return len(self._blobs)


def _leaf_hash(path: str, content_hash: str) -> bytes:
    return hashlib.sha256(f"{path}\x00{content_hash}".encode("utf-8")).digest()


def merkle_root(entries: list[tuple[str, str]]) -> str:
    """Merkle root over (path, content-hash) pairs, sorted by path.

    The empty tree has the hash of the empty string as its root.
    Odd nodes are promoted unchanged to the next level.
    """
    leaves = sorted(entries, key=lambda e: e[0])
    if not leaves:
        return sha256_hex(b"")
    level = [_leaf_hash(path, digest) for path, digest in leaves]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(hashlib.sha256(level[i] + level[i + 1]).digest())
        if len(level) % 2 == 1:
            nxt.append(level[-1])
        level = nxt
    return level[0].hex()


def merkle_proof(
    entries: list[tuple[str, str]], path: str
) -> list[tuple[str, bool]]:
    """Inclusion proof for *path*: a list of (sibling_hash, sibling_is_left).

    Raises KeyError if *path* is not in the tree.
    """
    leaves = sorted(entries, key=lambda e: e[0])
    paths = [p for p, _ in leaves]
    if path not in paths:
        raise KeyError(path)
    idx = paths.index(path)
    level = [_leaf_hash(p, h) for p, h in leaves]
    proof: list[tuple[str, bool]] = []
    while len(level) > 1:
        if idx % 2 == 0:
            if idx + 1 < len(level):
                proof.append((level[idx + 1].hex(), False))  # sibling on right
        else:
            proof.append((level[idx - 1].hex(), True))  # sibling on left
        nxt = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(hashlib.sha256(level[i] + level[i + 1]).digest())
        if len(level) % 2 == 1:
            nxt.append(level[-1])
        level = nxt
        idx //= 2
    return proof


def verify_proof(
    root: str, path: str, content_hash: str, proof: list[tuple[str, bool]]
) -> bool:
    """Recompute the root from a leaf and its proof; True iff it matches."""
    current = _leaf_hash(path, content_hash)
    for sibling_hex, sibling_is_left in proof:
        sibling = bytes.fromhex(sibling_hex)
        if sibling_is_left:
            current = hashlib.sha256(sibling + current).digest()
        else:
            current = hashlib.sha256(current + sibling).digest()
    return current.hex() == root
