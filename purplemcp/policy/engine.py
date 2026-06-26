"""MCP Policy Engine — YAML-configurable governance rules.

JHU MSSI Capstone, Layer 3 (policy / governance). Rules are authored in YAML
(see ``rules/``) and evaluated against a tool call + context. The condition
language is a small, **safe** DSL — no ``eval`` — supporting dotted fact paths,
``==`` / ``!=`` / ``contains`` / ``not contains`` comparisons and ``AND`` / ``OR``
connectors, which is everything the bundled compliance templates need.

Each rule carries an ``action`` (BLOCK / REQUIRE_HUMAN_APPROVAL / LOG_AND_ALERT)
and the legal ``article`` it enforces, so a decision is traceable straight back
to GDPR / EU AI Act / SOC 2 text.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

RULES_DIR = Path(__file__).resolve().parent / "rules"

# Action precedence: the strongest action among triggered rules wins.
_ACTION_RANK = {
    "EXECUTE": 0,
    "LOG_AND_ALERT": 1,
    "REQUIRE_HUMAN_APPROVAL": 2,
    "BLOCK": 3,
}

_MISSING = object()


# --------------------------------------------------------------------------- #
#  safe condition evaluation
# --------------------------------------------------------------------------- #
def _resolve(path: str, ctx: dict) -> Any:
    cur: Any = ctx
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return _MISSING
    return cur


def _value(token: str, ctx: dict) -> Any:
    token = token.strip()
    low = token.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if (token.startswith('"') and token.endswith('"')) or (token.startswith("'") and token.endswith("'")):
        return token[1:-1]
    if token.lstrip("-").isdigit():
        return int(token)
    # A dotted token that resolves is a fact reference; otherwise a bare literal.
    if "." in token:
        resolved = _resolve(token, ctx)
        if resolved is not _MISSING:
            return resolved
    return token


def _eval_clause(clause: str, ctx: dict) -> bool:
    clause = clause.strip()
    for op in (" not contains ", " contains ", " != ", " == "):
        if op in clause:
            left_s, right_s = clause.split(op, 1)
            left = _resolve(left_s.strip(), ctx)
            right = _value(right_s.strip(), ctx)
            # A missing fact never satisfies a comparison — we can't assert
            # equality *or* inequality about a value we don't have. (This keeps
            # `actual != declared` from firing on tools that declare neither.)
            if left is _MISSING:
                return False
            if op == " == ":
                return left == right
            if op == " != ":
                return left != right
            if op == " contains ":
                return _contains(left, right)
            if op == " not contains ":
                return not _contains(left, right)
    # No operator: bare path → truthiness.
    val = _resolve(clause, ctx)
    return bool(val) and val is not _MISSING


def _contains(container: Any, item: Any) -> bool:
    try:
        return item in container
    except TypeError:
        return False


def evaluate_condition(condition: str, ctx: dict) -> bool:
    """Evaluate a DSL condition string against ``ctx``. Disjunction of conjunctions."""
    if not condition or not condition.strip():
        return False
    for or_term in condition.split(" OR "):
        if all(_eval_clause(c, ctx) for c in or_term.split(" AND ")):
            return True
    return False


# --------------------------------------------------------------------------- #
#  decision
# --------------------------------------------------------------------------- #
@dataclass
class PolicyDecision:
    decision: str                                   # EXECUTE | BLOCK | REQUIRE_HUMAN_APPROVAL | LOG_AND_ALERT
    triggered_rules: list[dict] = field(default_factory=list)
    compliance_flags: list[str] = field(default_factory=list)   # articles violated
    human_approval_reason: Optional[str] = None

    @property
    def blocked(self) -> bool:
        return self.decision == "BLOCK"

    def to_dict(self) -> dict:
        return {
            "decision": self.decision,
            "triggered_rules": self.triggered_rules,
            "compliance_flags": self.compliance_flags,
            "human_approval_reason": self.human_approval_reason,
        }


# --------------------------------------------------------------------------- #
#  engine
# --------------------------------------------------------------------------- #
class PolicyEngine:
    """Evaluate tool calls against the YAML rules under ``rules_dir``."""

    def __init__(self, rules_dir: Optional[Path] = None) -> None:
        self.rules_dir = Path(rules_dir) if rules_dir else RULES_DIR
        self.policies: list[dict] = []
        self.reload()

    def reload(self) -> None:
        """(Re)load every ``*.yaml`` policy file from the rules directory."""
        self.policies = []
        for path in sorted(self.rules_dir.glob("*.yaml")):
            try:
                data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            except yaml.YAMLError:
                continue
            data["_file"] = path.name
            self.policies.append(data)

    @property
    def rule_count(self) -> int:
        return sum(len(p.get("rules", [])) for p in self.policies)

    def evaluate(self, tool_call: dict, context: Optional[dict] = None) -> PolicyDecision:
        """Evaluate one tool call; returns the strongest triggered action."""
        context = context or {}
        ctx = {
            "tool": tool_call,
            "data": tool_call.get("data", {}),
            "context": context,
        }
        triggered: list[dict] = []
        for policy in self.policies:
            for rule in policy.get("rules", []):
                if evaluate_condition(rule.get("condition", ""), ctx):
                    triggered.append({
                        "id": rule.get("id", "?"),
                        "name": rule.get("name", ""),
                        "action": rule.get("action", "LOG_AND_ALERT"),
                        "article": rule.get("article", ""),
                        "policy": policy.get("name", policy.get("_file", "")),
                    })

        if not triggered:
            return PolicyDecision(decision="EXECUTE")

        winner = max(triggered, key=lambda r: _ACTION_RANK.get(r["action"], 0))
        approval = next(
            (r for r in triggered if r["action"] == "REQUIRE_HUMAN_APPROVAL"), None
        )
        return PolicyDecision(
            decision=winner["action"],
            triggered_rules=triggered,
            compliance_flags=[r["article"] for r in triggered if r["article"]],
            human_approval_reason=(approval["name"] if approval else None),
        )
