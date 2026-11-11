"""Tests for tessell: store/Merkle, packages, builders, quorum, log, resolver."""

import copy
import unittest

from tessell.builder import Attestation, Builder, KeyRegistry, MaliciousBuilder
from tessell.log import BuildLog
from tessell.package import Package
from tessell.quorum import QuorumCoordinator
from tessell.resolver import Resolver, VerificationError
from tessell.store import (
    ContentStore,
    merkle_proof,
    merkle_root,
    sha256_hex,
    verify_proof,
)


def sample_package() -> Package:
    return Package(
        name="hello-app",
        version="1.0.0",
        sources={
            "src/main.py": b"print('hello, world')\n",
            "src/util.py": b"def greet(name):\n    return f'hello, {name}'\n",
            "README.md": b"# hello-app\n",
        },
    )


def make_builders(n_honest: int, n_malicious: int, registry: KeyRegistry):
    builders = [
        Builder(f"honest-{i}", f"key-honest-{i}".encode(), registry)
        for i in range(n_honest)
    ]
    builders += [
        MaliciousBuilder(f"evil-{i}", f"key-evil-{i}".encode(), registry)
        for i in range(n_malicious)
    ]
    return builders


class TestStoreAndMerkle(unittest.TestCase):
    def test_put_get_roundtrip(self):
        store = ContentStore()
        digest = store.put(b"hello")
        self.assertEqual(digest, sha256_hex(b"hello"))
        self.assertEqual(store.get(digest), b"hello")
        self.assertIsNone(store.get("0" * 64))
        self.assertIn(digest, store)

    def test_merkle_root_is_order_independent(self):
        entries = [("b.txt", sha256_hex(b"B")), ("a.txt", sha256_hex(b"A"))]
        self.assertEqual(merkle_root(entries), merkle_root(list(reversed(entries))))

    def test_merkle_proof_verifies_each_leaf(self):
        entries = [(f"file{i}.txt", sha256_hex(f"content {i}".encode())) for i in range(5)]
        root = merkle_root(entries)
        for path, digest in entries:
            proof = merkle_proof(entries, path)
            self.assertTrue(verify_proof(root, path, digest, proof))

    def test_merkle_proof_fails_on_wrong_content(self):
        entries = [("a.txt", sha256_hex(b"A")), ("b.txt", sha256_hex(b"B"))]
        root = merkle_root(entries)
        proof = merkle_proof(entries, "a.txt")
        self.assertFalse(verify_proof(root, "a.txt", sha256_hex(b"tampered"), proof))

    def test_merkle_proof_fails_on_tampered_proof(self):
        entries = [("a.txt", sha256_hex(b"A")), ("b.txt", sha256_hex(b"B"))]
        root = merkle_root(entries)
        proof = merkle_proof(entries, "a.txt")
        tampered = [(("0" * 64), left) for _, left in proof]
        self.assertFalse(verify_proof(root, "a.txt", sha256_hex(b"A"), tampered))

    def test_merkle_proof_unknown_path_raises(self):
        with self.assertRaises(KeyError):
            merkle_proof([("a.txt", sha256_hex(b"A"))], "nope.txt")


class TestPackage(unittest.TestCase):
    def test_build_is_deterministic(self):
        pkg = sample_package()
        self.assertEqual(pkg.build(), sample_package().build())

    def test_manifest_hash_changes_when_source_changes(self):
        pkg = sample_package()
        changed = Package(
            "hello-app",
            "1.0.0",
            {**pkg.sources, "src/main.py": b"print('different')\n"},
        )
        self.assertNotEqual(pkg.manifest_hash(), changed.manifest_hash())
        self.assertNotEqual(pkg.build(), changed.build())

    def test_manifest_hash_stable_across_dict_order(self):
        pkg = sample_package()
        reordered = Package(
            "hello-app",
            "1.0.0",
            dict(reversed(list(pkg.sources.items()))),
        )
        self.assertEqual(pkg.manifest_hash(), reordered.manifest_hash())


class TestBuilders(unittest.TestCase):
    def test_honest_builders_agree_byte_for_byte(self):
        registry = KeyRegistry()
        builders = make_builders(3, 0, registry)
        pkg = sample_package()
        outputs = {b.build(pkg)[0] for b in builders}
        self.assertEqual(len(outputs), 1)

    def test_attestations_verify(self):
        registry = KeyRegistry()
        builder = Builder("a", b"key-a", registry)
        _, att = builder.build(sample_package())
        self.assertTrue(registry.verify(att))

    def test_attestation_with_wrong_key_fails(self):
        registry = KeyRegistry()
        builder = Builder("a", b"key-a", registry)
        _, att = builder.build(sample_package())
        forged = Attestation(att.builder_id, att.package_hash, att.output_hash, "0" * 64)
        self.assertFalse(registry.verify(forged))

    def test_malicious_builder_output_differs_but_signature_verifies(self):
        # The honest limitation, stated explicitly: a signature proves *who*
        # built an output, not that the output is correct. Quorum catches it.
        registry = KeyRegistry()
        honest = Builder("a", b"key-a", registry)
        evil = MaliciousBuilder("evil", b"key-evil", registry)
        pkg = sample_package()
        honest_out, _ = honest.build(pkg)
        evil_out, evil_att = evil.build(pkg)
        self.assertNotEqual(honest_out, evil_out)
        self.assertIn(b"injected payload", evil_out)
        self.assertTrue(registry.verify(evil_att))


class TestQuorum(unittest.TestCase):
    def test_honest_quorum_publishes(self):
        store, registry = ContentStore(), KeyRegistry()
        coord = QuorumCoordinator(store, registry, quorum=3)
        result = coord.collect(sample_package(), make_builders(3, 0, registry))
        self.assertTrue(result.published)
        self.assertEqual(len(result.attestations), 3)
        self.assertIn(result.output_hash, store)

    def test_malicious_builder_rejected_by_quorum(self):
        store, registry = ContentStore(), KeyRegistry()
        coord = QuorumCoordinator(store, registry, quorum=3)
        result = coord.collect(sample_package(), make_builders(3, 1, registry))
        self.assertTrue(result.published)
        self.assertEqual(result.counts[result.output_hash], 3)
        self.assertEqual(result.disagreeing, ["evil-0"])
        self.assertEqual(result.invalid, [])
        # The published output contains no injected payload.
        self.assertNotIn(b"injected payload", store.get(result.output_hash))

    def test_no_quorum_when_builders_disagree(self):
        store, registry = ContentStore(), KeyRegistry()
        coord = QuorumCoordinator(store, registry, quorum=3)
        builders = make_builders(2, 2, registry)
        # Distinct tampers so the two malicious builders disagree too.
        builders[3].TAMPER_MARKER = b"\n# injected payload: different attack\n"
        result = coord.collect(sample_package(), builders)
        self.assertFalse(result.published)
        self.assertIsNone(result.output_hash)
        self.assertEqual(len(store), 0)

    def test_smaller_quorum_publishes_with_two_honest(self):
        store, registry = ContentStore(), KeyRegistry()
        coord = QuorumCoordinator(store, registry, quorum=2)
        result = coord.collect(sample_package(), make_builders(2, 1, registry))
        self.assertTrue(result.published)

    def test_quorum_assumes_honest_majority(self):
        # Documented threat-model boundary: if malicious builders reach the
        # quorum threshold with an identical tampered output, it publishes.
        # Quorum security requires an honest majority; no quorum scheme
        # avoids that assumption.
        store, registry = ContentStore(), KeyRegistry()
        coord = QuorumCoordinator(store, registry, quorum=3)
        result = coord.collect(sample_package(), make_builders(2, 3, registry))
        self.assertTrue(result.published)
        self.assertIn(b"injected payload", store.get(result.output_hash))


class TestBuildLog(unittest.TestCase):
    def test_append_and_verify(self):
        log = BuildLog()
        log.append({"event": "published", "package_hash": "a"})
        log.append({"event": "published", "package_hash": "b"})
        self.assertTrue(log.verify())
        self.assertEqual(len(log.entries), 2)

    def test_tampered_payload_breaks_verification(self):
        log = BuildLog()
        log.append({"event": "published", "package_hash": "a"})
        tampered = copy.deepcopy(log)
        entry = tampered.entries[0]
        tampered.entries[0] = type(entry)(
            entry.index, entry.prev_hash, {"event": "published", "package_hash": "X"},
            entry.entry_hash,
        )
        self.assertFalse(tampered.verify())

    def test_inclusion_proof_verifies(self):
        log = BuildLog()
        for i in range(4):
            log.append({"event": "published", "package_hash": f"pkg-{i}"})
        for i in range(4):
            self.assertTrue(log.verify_inclusion(i))

    def test_find_publish(self):
        log = BuildLog()
        log.append({"event": "published", "package_hash": "p", "output_hash": "o"})
        self.assertIsNotNone(log.find_publish("p", "o"))
        self.assertIsNone(log.find_publish("p", "other"))


class TestResolver(unittest.TestCase):
    def _published_setup(self, n_honest=3, n_malicious=1, quorum=3):
        store, registry, log = ContentStore(), KeyRegistry(), BuildLog()
        coord = QuorumCoordinator(store, registry, quorum=quorum)
        pkg = sample_package()
        result = coord.collect(pkg, make_builders(n_honest, n_malicious, registry))
        assert result.published
        log.append(
            {
                "event": "published",
                "package_hash": result.package_hash,
                "output_hash": result.output_hash,
                "builders": sorted(a.builder_id for a in result.attestations),
            }
        )
        return store, registry, log, result

    def test_install_honest_package(self):
        store, registry, log, result = self._published_setup()
        resolver = Resolver(store, registry, log, quorum=3)
        output = resolver.install(
            result.package_hash, result.output_hash, result.attestations
        )
        self.assertEqual(output, sample_package().build())

    def test_install_rejects_wrong_output_hash(self):
        store, registry, log, result = self._published_setup()
        resolver = Resolver(store, registry, log, quorum=3)
        with self.assertRaises(VerificationError):
            resolver.install(result.package_hash, "0" * 64, result.attestations)

    def test_install_rejects_forged_attestation(self):
        store, registry, log, result = self._published_setup()
        forged = list(result.attestations)
        forged[0] = Attestation(
            forged[0].builder_id,
            forged[0].package_hash,
            forged[0].output_hash,
            "0" * 64,
        )
        resolver = Resolver(store, registry, log, quorum=3)
        with self.assertRaises(VerificationError):
            resolver.install(result.package_hash, result.output_hash, forged)

    def test_install_rejects_insufficient_quorum(self):
        store, registry, log, result = self._published_setup()
        resolver = Resolver(store, registry, log, quorum=3)
        with self.assertRaises(VerificationError):
            resolver.install(
                result.package_hash, result.output_hash, result.attestations[:2]
            )

    def test_install_rejects_missing_log_entry(self):
        store, registry = ContentStore(), KeyRegistry()
        log = BuildLog()  # empty: no publish entry
        coord = QuorumCoordinator(store, registry, quorum=3)
        result = coord.collect(sample_package(), make_builders(3, 0, registry))
        resolver = Resolver(store, registry, log, quorum=3)
        with self.assertRaises(VerificationError):
            resolver.install(
                result.package_hash, result.output_hash, result.attestations
            )

    def test_install_rejects_tampered_log(self):
        store, registry, log, result = self._published_setup()
        tampered = copy.deepcopy(log)
        entry = tampered.entries[0]
        tampered.entries[0] = type(entry)(
            entry.index, entry.prev_hash, {"event": "published", "package_hash": "X"},
            entry.entry_hash,
        )
        resolver = Resolver(store, registry, tampered, quorum=3)
        with self.assertRaises(VerificationError):
            resolver.install(
                result.package_hash, result.output_hash, result.attestations
            )


if __name__ == "__main__":
    unittest.main()
