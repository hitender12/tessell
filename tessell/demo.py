"""Runnable demo: honest quorum publishes, a tampering builder is rejected,
a no-quorum case fails, and the build log proves its own integrity.
"""

from __future__ import annotations

from .builder import Builder, KeyRegistry, MaliciousBuilder
from .log import BuildLog
from .package import Package
from .quorum import QuorumCoordinator
from .resolver import Resolver, VerificationError
from .store import ContentStore


def _sample_package() -> Package:
    return Package(
        name="hello-app",
        version="1.0.0",
        sources={
            "src/main.py": b"print('hello, world')\n",
            "src/util.py": b"def greet(name):\n    return f'hello, {name}'\n",
            "README.md": b"# hello-app\n",
        },
    )


def run_demo() -> None:
    store = ContentStore()
    registry = KeyRegistry()
    log = BuildLog()
    package = _sample_package()
    print(f"Package hello-app 1.0.0, manifest hash: {package.manifest_hash()}\n")

    # -- Scenario A: 3 honest builders + 1 malicious, quorum 3 --------------
    print("=== Scenario A: 3 honest + 1 malicious builder, quorum 3 ===")
    builders = [
        Builder("builder-a", b"key-a", registry),
        Builder("builder-b", b"key-b", registry),
        Builder("builder-c", b"key-c", registry),
        MaliciousBuilder("builder-evil", b"key-evil", registry),
    ]
    coordinator = QuorumCoordinator(store, registry, quorum=3)
    result = coordinator.collect(package, builders)
    print(f"published: {result.published} ({result.reason})")
    print(f"attestation counts by output hash: {result.counts}")
    print(f"disagreeing builders: {result.disagreeing}")
    print(f"invalid attestations: {result.invalid}")
    assert result.published and result.output_hash is not None

    entry = log.append(
        {
            "event": "published",
            "package_hash": result.package_hash,
            "output_hash": result.output_hash,
            "builders": sorted(a.builder_id for a in result.attestations),
        }
    )
    print(f"logged publish event at index {entry.index}, "
          f"entry hash {entry.entry_hash[:16]}...")
    print(f"log verifies: {log.verify()}")
    print(f"log merkle root: {log.merkle_root()[:16]}...")
    print(f"inclusion proof for entry 0 verifies: {log.verify_inclusion(0)}")

    resolver = Resolver(store, registry, log, quorum=3)
    installed = resolver.install(
        result.package_hash, result.output_hash, result.attestations
    )
    print(f"resolver installed {len(installed)} bytes; "
          f"tamper marker present: {b'injected payload' in installed}")
    print()

    # -- Scenario B: no quorum (2 honest + 2 malicious, different tampers) ---
    print("=== Scenario B: 2 honest + 2 malicious builders, quorum 3 ===")
    builders_b = [
        Builder("builder-a", b"key-a", registry),
        Builder("builder-b", b"key-b", registry),
        MaliciousBuilder("builder-evil", b"key-evil", registry),
        MaliciousBuilder("builder-evil2", b"key-evil2", registry),
    ]
    # Give the second malicious builder a *different* tamper so the two
    # malicious outputs disagree with each other as well.
    builders_b[3].TAMPER_MARKER = b"\n# injected payload: different attack\n"
    result_b = coordinator.collect(package, builders_b)
    print(f"published: {result_b.published} ({result_b.reason})")
    print(f"attestation counts by output hash: {result_b.counts}")
    print()

    # -- Scenario C: tamper with the log, verification must fail -------------
    print("=== Scenario C: tamper with a log entry, then verify ===")
    import copy

    tampered = copy.deepcopy(log)
    entry0 = tampered.entries[0]
    tampered.entries[0] = type(entry0)(
        entry0.index,
        entry0.prev_hash,
        {**entry0.payload, "output_hash": "0" * 64},
        entry0.entry_hash,
    )
    print(f"original log verifies: {log.verify()}")
    print(f"tampered log verifies: {tampered.verify()}")
    try:
        Resolver(store, registry, tampered, quorum=3).install(
            result.package_hash, result.output_hash, result.attestations
        )
        print("resolver installed from tampered log (UNEXPECTED)")
    except VerificationError as exc:
        print(f"resolver refused install from tampered log: {exc}")
