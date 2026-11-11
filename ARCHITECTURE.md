# Tessell architecture

## Data flow

```
Package (name, version, sources)
        │
        ▼
manifest hash = Merkle root over (path, content-hash) pairs
        │
        ├─► Builder.build() ──► deterministic output bytes
        │                      + HMAC attestation (builder, manifest, output)
        │
        ▼
QuorumCoordinator.collect()
   1. verify every attestation (signature + manifest + output hash match)
   2. group verified attestations by output hash
   3. publish iff one hash has >= quorum attestations
   4. store the winning output in the content-addressed store
        │
        ▼
BuildLog.append({"event": "published", ...})   hash-chained entry
        │
        ▼
Resolver.install(package_hash, output_hash, attestations)
   1. >= quorum distinct valid attestations for this exact pair
   2. output present in store and hashing to the claimed hash
   3. log chain verifies AND contains a matching publish entry
   ──► output bytes, or VerificationError
```

## Components

### store.py — content addressing and Merkle trees

- `ContentStore`: dict from SHA-256 hex digest to bytes. `put` returns the
  hash; `get` returns bytes or `None`.
- Merkle tree over sorted `(path, content_hash)` pairs. Leaf hash is
  `SHA-256(path || 0x00 || content_hash)`; internal nodes hash the
  concatenation of children; odd nodes are promoted unchanged. The empty
  tree's root is the hash of the empty string.
- `merkle_proof` / `verify_proof` implement standard inclusion proofs:
  a list of `(sibling_hash, sibling_is_left)` steps that recompute the
  root from a leaf.

### package.py — packages as pure functions

- `Package.manifest_hash()` is the Merkle root over the package's sources
  — the package's content identity. Reordering the sources dict does not
  change it; changing any byte of any source does.
- `Package.build()` is deterministic by construction: a format header, the
  manifest hash, then the sources in sorted path order with explicit
  lengths. No timestamps, no randomness, no environment dependence.

### builder.py — builders and attestations

- `Builder` runs `package.build()` and signs
  `HMAC(key, "manifest_hash:output_hash")`. The `KeyRegistry` maps builder
  ids to keys and verifies signatures with constant-time comparison.
- `MaliciousBuilder` appends a fixed payload and *validly signs* the
  result. This models the real supply-chain attack: the signature is
  genuine, the output is not. The design never relies on a builder's
  honesty — only on quorum agreement.
- Production note: HMAC + registry stands in for Ed25519 signatures
  against a public-key directory. The sign/verify boundary is the same.

### quorum.py — the coordinator

- `collect(package, builders)` builds with every builder, discards
  attestations that fail verification or do not match the bytes actually
  produced, groups the rest by output hash, and publishes the largest
  group iff it reaches `quorum`. Ties break deterministically by output
  hash so results do not depend on iteration order.
- The result reports per-hash attestation counts, disagreeing builder ids,
  and invalid attestation ids, so disagreement is observable.
- Published results are recorded in `coordinator.published` by manifest
  hash; the winning output is stored in the content store.

### log.py — tamper-evident build log

- Each entry commits to `prev_hash` and a canonical JSON encoding of its
  payload (`sort_keys=True`, tight separators), so any edit to any entry
  breaks every subsequent hash.
- `verify()` recomputes the whole chain. Entries double as Merkle leaves
  (keyed by index), giving `inclusion_proof` / `verify_inclusion` for
  compact proof that a publish event is in the log.
- `find_publish(package_hash, output_hash)` is what the resolver uses to
  confirm a publish event exists.

### resolver.py — verify before install

Install is all-or-nothing: quorum of distinct valid attestations for the
exact pair, output present in the store with a matching hash, and a
verified log containing the publish entry. Any failure raises
`VerificationError` with the reason; nothing is installed partially.

## Threat model

- **Assumed honest majority** among builders for the chosen quorum. If
  malicious builders reach the quorum with an identical tampered output,
  it publishes. This is inherent to quorum schemes and is covered by an
  explicit test rather than assumed away. Mitigations in production:
  builder diversity (different OS/toolchains/operators) and reputation.
- **The coordinator is trusted to count honestly** in this version: it
  verifies attestations but a compromised coordinator could lie about the
  count. In production the resolver would re-verify the attestation set
  itself (it already does) and the log would be public and auditable.
- **The key registry is a stand-in** for a key-transparency log. A
  compromised registry could substitute keys; production needs
  append-only, publicly auditable key distribution.
- **No sandboxing yet.** Builders are in-process; a malicious builder in
  this simulation can only tamper with its own output bytes. Real
  builders need container/WASM isolation so a compromised build cannot
  affect the coordinator or other builders.
