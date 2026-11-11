"""Quorum coordinator: publish only on builder agreement.

The coordinator asks N builders to build the same package, verifies every
attestation, and groups the *verified* attestations by output hash.  A
package is published only when one output hash has at least ``quorum``
verified attestations from distinct builders.  The published output is
stored in the content-addressed store under its hash.

Security rests on an honest majority among the builders for the chosen
quorum: if malicious builders outnumber the quorum, a tampered output can
publish.  That is a property of any quorum scheme, not a bug — it is
documented in ARCHITECTURE.md and demonstrated by a test.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .builder import Attestation, Builder, KeyRegistry
from .package import Package
from .store import ContentStore, sha256_hex


@dataclass
class QuorumResult:
    published: bool
    package_hash: str
    output_hash: str | None
    attestations: list[Attestation] = field(default_factory=list)
    # output hash -> number of verified attestations for it
    counts: dict[str, int] = field(default_factory=dict)
    # builder ids whose verified output differed from the published one
    disagreeing: list[str] = field(default_factory=list)
    # builder ids whose attestations failed verification entirely
    invalid: list[str] = field(default_factory=list)
    reason: str = ""


class QuorumCoordinator:
    def __init__(self, store: ContentStore, registry: KeyRegistry, quorum: int):
        if quorum < 1:
            raise ValueError("quorum must be >= 1")
        self.store = store
        self.registry = registry
        self.quorum = quorum
        self.published: dict[str, QuorumResult] = {}

    def collect(self, package: Package, builders: list[Builder]) -> QuorumResult:
        package_hash = package.manifest_hash()
        groups: dict[str, list[Attestation]] = {}
        outputs: dict[str, bytes] = {}
        invalid: list[str] = []

        for builder in builders:
            output, attestation = builder.build(package)
            # Verify the attestation *and* that it matches what was built.
            if (
                not self.registry.verify(attestation)
                or attestation.package_hash != package_hash
                or attestation.output_hash != sha256_hex(output)
            ):
                invalid.append(builder.builder_id)
                continue
            groups.setdefault(attestation.output_hash, []).append(attestation)
            outputs.setdefault(attestation.output_hash, output)

        counts = {h: len(atts) for h, atts in groups.items()}
        if not groups:
            return QuorumResult(False, package_hash, None, [], counts, [], invalid,
                                "no verified attestations received")

        # Largest group wins; ties are broken deterministically by hash so
        # the result does not depend on builder iteration order.
        best_hash = max(groups, key=lambda h: (len(groups[h]), h))
        best_atts = groups[best_hash]
        if len(best_atts) < self.quorum:
            disagreeing = [
                att.builder_id
                for h, atts in groups.items()
                if h != best_hash
                for att in atts
            ]
            return QuorumResult(
                False, package_hash, None, [], counts, disagreeing, invalid,
                f"no output reached quorum {self.quorum} "
                f"(best: {len(best_atts)})",
            )

        self.store.put(outputs[best_hash])
        disagreeing = [
            att.builder_id
            for h, atts in groups.items()
            if h != best_hash
            for att in atts
        ]
        result = QuorumResult(
            True, package_hash, best_hash, best_atts, counts, disagreeing,
            invalid, f"quorum {len(best_atts)}/{len(builders)} reached",
        )
        self.published[package_hash] = result
        return result
