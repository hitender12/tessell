"""Client resolver: verify everything before installing.

``install`` refuses unless *all* of these hold:

1. At least ``quorum`` distinct builders attested to this exact
   (package hash, output hash), and every attestation verifies.
2. The output bytes are present in the content-addressed store and hash
   to the claimed output hash.
3. The build log verifies as a chain *and* contains a matching ``published``
   entry for this package/output pair.

Any failure raises :class:`VerificationError` with the reason — nothing is
installed on a partial or forged claim.
"""

from __future__ import annotations

from .builder import Attestation, KeyRegistry
from .log import BuildLog
from .store import ContentStore, sha256_hex


class VerificationError(Exception):
    """Raised when a package cannot be verified for install."""


class Resolver:
    def __init__(
        self,
        store: ContentStore,
        registry: KeyRegistry,
        log: BuildLog,
        quorum: int,
    ):
        self.store = store
        self.registry = registry
        self.log = log
        self.quorum = quorum

    def install(
        self, package_hash: str, output_hash: str, attestations: list[Attestation]
    ) -> bytes:
        # 1. Quorum of distinct, valid attestations for this exact pair.
        distinct: set[str] = set()
        for att in attestations:
            if att.package_hash != package_hash or att.output_hash != output_hash:
                raise VerificationError(
                    f"attestation from {att.builder_id} is for a different "
                    "package/output pair"
                )
            if not self.registry.verify(att):
                raise VerificationError(
                    f"attestation from {att.builder_id} failed signature verification"
                )
            distinct.add(att.builder_id)
        if len(distinct) < self.quorum:
            raise VerificationError(
                f"only {len(distinct)} distinct valid attestations, "
                f"quorum is {self.quorum}"
            )

        # 2. Output present in the store and matching its claimed hash.
        output = self.store.get(output_hash)
        if output is None:
            raise VerificationError("output bytes not found in content store")
        if sha256_hex(output) != output_hash:
            raise VerificationError("stored output does not match its hash")

        # 3. The publish event is in a verified, untampered log.
        if not self.log.verify():
            raise VerificationError("build log failed chain verification")
        if self.log.find_publish(package_hash, output_hash) is None:
            raise VerificationError(
                "no matching publish entry in the build log"
            )

        return output
