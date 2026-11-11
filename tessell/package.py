"""Packages as pure functions of their content.

A package is a name, a version, and a set of source files.  Its identity is
its *manifest hash* — the Merkle root over its (path, content-hash) pairs —
so two packages with the same sources are the same package, and any change
to any source changes the identity.

``Package.build()`` is the deterministic build function: given the same
sources it always produces byte-identical output, because it only depends
on the sorted sources and the manifest hash.  That determinism is what
makes builder quorum meaningful: honest builders must agree exactly.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .store import merkle_root, sha256_hex

BUILD_FORMAT_VERSION = "TESSELL-BUILD-v1"


@dataclass(frozen=True)
class Package:
    name: str
    version: str
    sources: dict[str, bytes] = field(default_factory=dict)

    def source_hashes(self) -> dict[str, str]:
        return {path: sha256_hex(content) for path, content in self.sources.items()}

    def manifest_hash(self) -> str:
        """The package's content identity: Merkle root over its sources."""
        return merkle_root(sorted(self.source_hashes().items()))

    def build(self) -> bytes:
        """Deterministic build: pure function of the sorted sources."""
        parts: list[bytes] = [
            f"{BUILD_FORMAT_VERSION}\n".encode("utf-8"),
            f"manifest:{self.manifest_hash()}\n".encode("utf-8"),
        ]
        for path in sorted(self.sources):
            content = self.sources[path]
            parts.append(f"file:{path}:{len(content)}\n".encode("utf-8"))
            parts.append(content)
            parts.append(b"\n")
        return b"".join(parts)
