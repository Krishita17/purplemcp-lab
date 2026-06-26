"""Tests for the Policy Engine + per-attack defense matrix (real YAML eval)."""

from __future__ import annotations

from purplemcp.crypto import CryptoMCP
from purplemcp.policy import PolicyEngine, evaluate_attack_defenses, evaluate_condition
from purplemcp.policy.engine import _MISSING, _resolve


# --------------------------------------------------------------------------- #
#  condition DSL
# --------------------------------------------------------------------------- #
def test_resolve_dotted_path():
    ctx = {"tool": {"publisher": {"trust_level": "UNTRUSTED"}}}
    assert _resolve("tool.publisher.trust_level", ctx) == "UNTRUSTED"
    assert _resolve("tool.missing.x", ctx) is _MISSING


def test_condition_operators():
    ctx = {
        "tool": {"capabilities": ["network_request", "credential_access"],
                 "actual": ["a", "b"], "declared": ["a"]},
        "data": {"contains_pii": True},
        "context": {"risk_level": "HIGH"},
    }
    assert evaluate_condition("tool.capabilities contains credential_access", ctx)
    assert not evaluate_condition("tool.capabilities contains filesystem_access", ctx)
    assert evaluate_condition("data.contains_pii == true", ctx)
    assert evaluate_condition("context.risk_level == HIGH AND data.contains_pii == true", ctx)
    assert not evaluate_condition("context.risk_level == LOW AND data.contains_pii == true", ctx)
    assert evaluate_condition("tool.actual != tool.declared", ctx)


def test_missing_fact_never_satisfies():
    # `actual != declared` must NOT fire when the facts are absent.
    assert not evaluate_condition("tool.actual_capabilities != tool.declared_capabilities", {"tool": {}})


# --------------------------------------------------------------------------- #
#  engine
# --------------------------------------------------------------------------- #
def test_engine_loads_rules():
    pe = PolicyEngine()
    assert pe.rule_count >= 5
    assert any(p["name"].startswith("GDPR") for p in pe.policies)


def test_block_beats_flag():
    pe = PolicyEngine()
    tool = {
        "publisher": {"trust_level": "UNTRUSTED"},
        "capabilities": ["network_request"],
        "declared_capabilities": ["x"], "actual_capabilities": ["x"],
        "crypto": {"verified": True},
        "data": {"contains_pii": True},
    }
    dec = pe.evaluate(tool, {"risk_level": "HIGH"})
    # GDPR-001 BLOCK and GDPR-003 LOG_AND_ALERT both fire -> BLOCK wins.
    assert dec.decision == "BLOCK"
    assert any("Art. 5(1)(f)" in a for a in dec.compliance_flags)


def test_clean_tool_executes():
    pe = PolicyEngine()
    tool = {
        "publisher": {"trust_level": "VERIFIED"},
        "capabilities": ["math"],
        "declared_capabilities": ["add"], "actual_capabilities": ["add"],
        "crypto": {"verified": True},
        "data": {"contains_pii": False},
    }
    assert pe.evaluate(tool, {"risk_level": "LOW"}).decision == "EXECUTE"


# --------------------------------------------------------------------------- #
#  per-attack defense matrix (the bench / viewer columns)
# --------------------------------------------------------------------------- #
def test_defense_matrix_maps_each_attack():
    pe, cm = PolicyEngine(), CryptoMCP()
    expect = {
        "tool_poisoning": ("BLOCKED", "BLOCK", "5(1)(f)"),
        "indirect_injection": ("N/A", "FLAG", "Art. 33"),
        "tool_shadowing": ("BLOCKED", "BLOCK", "Art. 15"),
        "rug_pull": ("BLOCKED", "BLOCK", "Art. 9"),
        "data_exfiltration": ("N/A", "BLOCK", "5(1)(f)"),
        "command_injection": ("N/A", "BLOCK", "Art. 9"),
    }
    for pid, (crypto, policy, article) in expect.items():
        d = evaluate_attack_defenses(pid, crypto=cm, policy=pe)
        assert d.crypto == crypto, f"{pid} crypto"
        assert d.policy == policy, f"{pid} policy"
        assert article in d.article, f"{pid} article {d.article!r}"


def test_crypto_only_applies_to_integrity_attacks():
    pe, cm = PolicyEngine(), CryptoMCP()
    # Description-integrity attacks: crypto blocks. Runtime attacks: N/A.
    assert evaluate_attack_defenses("tool_poisoning", crypto=cm, policy=pe).crypto == "BLOCKED"
    assert evaluate_attack_defenses("excessive_agency", crypto=cm, policy=pe).crypto == "N/A"
    assert evaluate_attack_defenses("prompt_override", crypto=cm, policy=pe).crypto == "N/A"
