# Tessell — trustless reproducible builds by builder quorum

"Reproducible builds" today rely on trusting a single builder. If that
builder is compromised, the published artifact is compromised — and nothing
in the pipeline notices, because the builder also signs the result.

Tessell removes the single point of trust: **a package publishes only
when a quorum of independent builders produces byte-identical output.**
A malicious builder can validly sign its own tampered output, but its
output hash disagrees with the honest builders', so the quorum rejects it.
Clients verify attestations, quorum, and the tamper-evident build log
before installing anything.

## The novel idea

1. **Packages are pure functions of content hashes.** A package's identity
   is the Merkle root over its (path, content-hash) pairs, and the build
   function is deterministic over the sorted sources. Honest builders
   *must* agree byte for byte — agreement is checkable, not assumed.
2. **Quorum, not trust.** The coordinator groups verified attestations by
   output hash and publishes only when one hash reaches the quorum
   threshold. Disagreement is visible (counts per output hash, disagreeing
   builder ids) instead of silently resolved.
3. **Verify-before-install, three ways.** The resolver refuses unless
   (a) a quorum of distinct builders attested to this exact
   package/output pair with valid signatures, (b) the output bytes are in
   the content store and hash to the claimed hash, and (c) the build log
   verifies as a chain and contains a matching publish entry.
4. **Tamper-evident log.** Publish events go into a hash-chained,
   append-only log whose entries are Merkle leaves, so clients get compact
   inclusion proofs instead of downloading history.

## Quickstart

Requires Python 3.10+ and nothing else (standard library only).

```bash
python -m tessell          # runnable demo: publish, rejection, log tampering
python -m unittest discover -s tests -v   # test suite (28 tests)
```

Use it as a library:

```python
from tessell import (Builder, KeyRegistry, MaliciousBuilder, Package,
                     QuorumCoordinator, BuildLog, Resolver, ContentStore)

store, registry, log = ContentStore(), KeyRegistry(), BuildLog()
package = Package("hello-app", "1.0.0", {"src/main.py": b"print('hi')\n"})

builders = [Builder("a", b"key-a", registry),
            Builder("b", b"key-b", registry),
            Builder("c", b"key-c", registry),
            MaliciousBuilder("evil", b"key-evil", registry)]

result = QuorumCoordinator(store, registry, quorum=3).collect(package, builders)
print(result.published, result.reason)   # True, "quorum 3/4 reached"
print(result.disagreeing)                # ['evil']
```

## Architecture

```
tessell/
  store.py     content-addressed store + Merkle root / proof / verify
  package.py   package identity (manifest hash) + deterministic build
  builder.py   honest + malicious builders, HMAC attestations, key registry
  quorum.py    coordinator: verify, group by output hash, publish on quorum
  log.py       hash-chained append-only build log + Merkle inclusion proofs
  resolver.py  client install: quorum + store + log checks, or refuse
  demo.py      runnable demo (publish, rejection, log tampering)
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design, the threat
model, and the limits.

## Honest status (v0.1.0)

What genuinely works:

- Content-addressed store, Merkle roots/proofs (order-independent,
  verified per leaf), deterministic builds, HMAC attestations.
- Quorum publish/reject in all tested configurations: 3 honest + 1
  malicious publishes the honest output; 2 honest + 2 disagreeing
  malicious builders fails to publish; forged signatures and wrong hashes
  are excluded before grouping. 28 tests pass.
- Build log chain verification, Merkle inclusion proofs, and resolver
  refusal on forged attestations, insufficient quorum, missing log
  entries, and tampered logs.

What is simplified or not claimed:

- **Simulated cryptography.** Attestations use HMAC with a shared key
  registry, standing in for a public-key directory. Production would use
  Ed25519 signatures and a real key-transparency log; the sign/verify
  interface is the same.
- **Simulated builders and sandboxing.** Builders are in-process Python
  objects running a toy deterministic build function, not sandboxed
  processes or containers. There is no real isolation, no network fetch,
  and no dependency resolution — the "build" is a canonical
  concatenation of the declared sources.
- **Quorum assumes an honest majority.** If malicious builders reach the
  quorum threshold with an identical tampered output, it publishes. That
  is a property of any quorum scheme, and it is covered by an explicit
  test (`test_quorum_assumes_honest_majority`) rather than hidden.
- **In-memory store and log.** Nothing is persisted to disk; a restart
  loses state.

## Evaluation plan

- **Correctness:** 28 unit/integration tests covering store, Merkle
  proofs, determinism, quorum publish/reject, log tampering, and resolver
  refusal cases.
- **Attack scenarios (demo):** honest quorum publishes; one malicious
  builder rejected; split builders fail to reach quorum; log tampering
  detected and install refused.
- **Overhead (future):** measure build-time cost of N-builder quorum vs.
  single-builder builds, and attestation/log sizes as the package count
  grows.
- **Hardening (future):** Ed25519 attestations, real sandboxed builders
  (containers/WASM), a persistent content store, and builder diversity
  scoring (different OS/toolchains) so a single toolchain bug cannot
  produce a false quorum.
