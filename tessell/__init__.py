"""Tessell: trustless reproducible builds by builder quorum.

Packages are pure functions of their content hashes.  A package publishes
only when a quorum of independent builders produces byte-identical output;
clients verify attestations, quorum, and the tamper-evident build log
before installing.
"""

from .builder import Attestation, Builder, KeyRegistry, MaliciousBuilder
from .log import BuildLog, LogEntry
from .package import Package
from .quorum import QuorumCoordinator, QuorumResult
from .resolver import Resolver, VerificationError
from .store import (
    ContentStore,
    merkle_proof,
    merkle_root,
    sha256_hex,
    verify_proof,
)

__all__ = [
    "Attestation",
    "Builder",
    "MaliciousBuilder",
    "KeyRegistry",
    "BuildLog",
    "LogEntry",
    "Package",
    "QuorumCoordinator",
    "QuorumResult",
    "Resolver",
    "VerificationError",
    "ContentStore",
    "merkle_proof",
    "merkle_root",
    "sha256_hex",
    "verify_proof",
]

__version__ = "0.1.0"
