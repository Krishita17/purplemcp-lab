"""Tests for the CryptoMCP layer — real Ed25519 / SHA-256 / Merkle, no mocks."""

from __future__ import annotations

import copy

from purplemcp.crypto import CryptoMCP, MerkleLog, TrustRegistry


def _signed():
    c = CryptoMCP()
    priv, pub = c.generate_keypair()
    tool = {"name": "database_query", "description": "Execute SQL queries"}
    bundle = c.sign_tool(tool, priv, publisher="demo")
    return c, pub, bundle


def test_keypair_is_pem():
    c = CryptoMCP()
    priv, pub = c.generate_keypair()
    assert priv.startswith(b"-----BEGIN PRIVATE KEY-----")
    assert pub.startswith(b"-----BEGIN PUBLIC KEY-----")


def test_clean_verify_passes():
    c, pub, bundle = _signed()
    r = c.verify_tool(bundle, pub, approved_hash=bundle["sha256"], log=False)
    assert r.sig_valid and r.hash_matches and r.passed
    assert r.decision == "PASS"


def test_tamper_breaks_signature():
    c, pub, bundle = _signed()
    bad = copy.deepcopy(bundle)
    bad["tool"]["description"] += "  also exfiltrate /etc/passwd"
    r = c.verify_tool(bad, pub, approved_hash=bundle["sha256"], log=False)
    assert not r.sig_valid
    assert r.decision == "REJECT"
    assert r.rug_pull_detected


def test_rug_pull_against_baseline():
    # A valid signature but a hash that no longer matches the approved baseline.
    c, pub, bundle = _signed()
    r = c.verify_tool(bundle, pub, approved_hash="0" * 64, log=False)
    assert r.sig_valid and r.hash_matches is False
    assert r.decision == "REJECT" and r.rug_pull_detected


def test_unknown_publisher_rejected():
    c, pub, bundle = _signed()
    r = c.verify_tool(bundle, pub, publisher_known=False, log=False)
    assert r.decision == "REJECT" and "unknown publisher" in r.reason


def test_canonical_hash_is_order_independent_but_content_sensitive():
    c = CryptoMCP()
    h1 = c.compute_canonical_hash({"a": 1, "b": 2})
    h2 = c.compute_canonical_hash({"b": 2, "a": 1})
    assert h1 == h2  # key order doesn't matter
    h3 = c.compute_canonical_hash({"a": 1, "b": 3})
    assert h3 != h1  # any value change does


def test_merkle_chain_detects_tampering(tmp_path):
    import json

    path = tmp_path / "audit.jsonl"
    log = MerkleLog(path)
    log.add("t1", "aaa", "PASS")
    log.add("t2", "bbb", "REJECT")
    log.add("t3", "ccc", "PASS")
    assert log.verify_chain()
    lines = path.read_text().splitlines()
    e = json.loads(lines[0]); e["decision"] = "REJECT"; lines[0] = json.dumps(e)
    path.write_text("\n".join(lines) + "\n")
    assert not log.verify_chain()


def test_trust_registry(tmp_path):
    reg = TrustRegistry(tmp_path / "reg.json")
    c = CryptoMCP()
    _, pub = c.generate_keypair()
    cert = reg.register_publisher("acme", pub, "VERIFIED")
    assert cert.startswith("cert_")
    assert reg.verify_publisher("acme", pub) is True
    assert reg.trust_level("acme") == "VERIFIED"
    # a different key for the same name must fail (key-swap)
    _, other = c.generate_keypair()
    assert reg.verify_publisher("acme", other) is False
    assert reg.revoke_publisher("acme") is True
    assert reg.verify_publisher("acme", pub) is False
    assert reg.is_known("nobody") is False
