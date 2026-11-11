"""Builders and attestations.

A builder runs the deterministic build function and signs an attestation
over (package manifest hash, output hash) with HMAC-SHA256.  The
``KeyRegistry`` stands in for a public-key directory: in production the
HMAC would be an Ed25519 signature verifiable with the builder's public
key; the interface (``sign`` / ``verify``) is the same.

Important honesty note: an attestation proves *who* built an output, not
that the output is correct.  A malicious builder can validly sign its own
tampered output — that is exactly what the quorum coordinator is for.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from .package import Package
from .store import sha256_hex


@dataclass(frozen=True)
class Attestation:
    builder_id: str
    package_hash: str
    output_hash: str
    signature: str  # hex HMAC-SHA256 over "package_hash:output_hash"


class KeyRegistry:
    """Maps builder ids to their (simulated) signing keys."""

    def __init__(self) -> None:
        self._keys: dict[str, bytes] = {}

    def register(self, builder_id: str, key: bytes) -> None:
        self._keys[builder_id] = key

    def key_for(self, builder_id: str) -> bytes | None:
        return self._keys.get(builder_id)

    @staticmethod
    def _message(package_hash: str, output_hash: str) -> bytes:
        return f"{package_hash}:{output_hash}".encode("utf-8")

    def sign(self, builder_id: str, package_hash: str, output_hash: str) -> str:
        key = self._keys.get(builder_id)
        if key is None:
            raise KeyError(f"unknown builder: {builder_id}")
        return hmac.new(key, self._message(package_hash, output_hash), hashlib.sha256).hexdigest()

    def verify(self, attestation: Attestation) -> bool:
        key = self._keys.get(attestation.builder_id)
        if key is None:
            return False
        expected = hmac.new(
            key,
            self._message(attestation.package_hash, attestation.output_hash),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, attestation.signature)


class Builder:
    """An honest builder: deterministic build + signed attestation."""

    def __init__(self, builder_id: str, key: bytes, registry: KeyRegistry):
        self.builder_id = builder_id
        self.key = key
        self.registry = registry
        registry.register(builder_id, key)

    def build(self, package: Package) -> tuple[bytes, Attestation]:
        output = package.build()
        return output, self._attest(package, output)

    def _attest(self, package: Package, output: bytes) -> Attestation:
        output_hash = sha256_hex(output)
        signature = self.registry.sign(
            self.builder_id, package.manifest_hash(), output_hash
        )
        return Attestation(self.builder_id, package.manifest_hash(), output_hash, signature)


class MaliciousBuilder(Builder):
    """A tampering builder: appends a payload, then *validly signs* it.

    Its attestation verifies cryptographically — it really built that
    output — but the output hash differs from the honest builders', so
    quorum rejects it.  This is the supply-chain attack the design stops.
    """

    TAMPER_MARKER = b"\n# injected payload: exfiltrate credentials\n"

    def build(self, package: Package) -> tuple[bytes, Attestation]:
        output = package.build() + self.TAMPER_MARKER
        return output, self._attest(package, output)
