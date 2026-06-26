"""CryptoMCP — Ed25519 digital signatures for MCP tool descriptions.

JHU MSSI Capstone, Layer 4 (cryptographic integrity):

- A tool *publisher* signs the tool descriptor at deploy time with Ed25519.
- An MCPShield verifies the signature **before the agent ever sees the tool**.
- A SHA-256 baseline of the canonical descriptor detects rug-pulls (the
  description silently changing after approval).
- A Merkle-chained audit log gives a tamper-evident record of every decision.

The crypto is real: signatures are produced and verified with the
``cryptography`` library's Ed25519 implementation, and hashes are real SHA-256
over canonicalized JSON, so any byte-level change to a tool description yields a
different hash and a failed signature.
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def _canonical_json(obj) -> bytes:
    """Deterministic JSON: sorted keys, no insignificant whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------- #
#  verification result
# --------------------------------------------------------------------------- #
@dataclass
class VerificationResult:
    sig_valid: bool                    # Ed25519 signature checks out
    hash_matches: Optional[bool]       # SHA-256 matches approved baseline (None if no baseline)
    rug_pull_detected: bool            # hash changed since approval
    publisher_known: bool              # publisher present in the trust registry
    decision: str                      # "PASS" | "REJECT" | "ALERT"
    reason: str                        # human-readable explanation
    recomputed_hash: str = ""          # SHA-256 we actually computed at verify time

    @property
    def passed(self) -> bool:
        return self.decision == "PASS"


# --------------------------------------------------------------------------- #
#  Merkle-chained audit log
# --------------------------------------------------------------------------- #
class MerkleLog:
    """Append-only, hash-chained audit log (tamper-evident).

    Each entry's hash = SHA-256(prev_hash || timestamp || tool_hash || decision),
    so altering any past entry breaks every subsequent link — exactly the
    property that makes the log tamper-evident.
    """

    GENESIS = "0" * 64

    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = Path(path) if path else None

    def entries(self) -> list[dict]:
        if not self.path or not self.path.exists():
            return []
        out = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                out.append(json.loads(line))
        return out

    @staticmethod
    def _entry_hash(prev_hash: str, timestamp: str, tool_hash: str, decision: str) -> str:
        return hashlib.sha256(
            f"{prev_hash}||{timestamp}||{tool_hash}||{decision}".encode("utf-8")
        ).hexdigest()

    def add(self, tool_name: str, tool_hash: str, decision: str) -> str:
        """Append one entry; returns its entry hash."""
        entries = self.entries()
        prev = entries[-1]["entry_hash"] if entries else self.GENESIS
        ts = _now_iso()
        entry_hash = self._entry_hash(prev, ts, tool_hash, decision)
        entry = {
            "index": len(entries) + 1,
            "timestamp": ts,
            "tool_name": tool_name,
            "tool_hash": tool_hash,
            "decision": decision,
            "prev_hash": prev,
            "entry_hash": entry_hash,
        }
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        return entry_hash

    def verify_chain(self) -> bool:
        """Recompute the whole chain from genesis; True iff every link is intact."""
        prev = self.GENESIS
        for e in self.entries():
            if e.get("prev_hash") != prev:
                return False
            expected = self._entry_hash(prev, e["timestamp"], e["tool_hash"], e["decision"])
            if e.get("entry_hash") != expected:
                return False
            prev = e["entry_hash"]
        return True

    def reset(self) -> None:
        if self.path and self.path.exists():
            self.path.unlink()


# --------------------------------------------------------------------------- #
#  CryptoMCP
# --------------------------------------------------------------------------- #
class CryptoMCP:
    """Ed25519 sign / verify for MCP tool descriptors + Merkle audit log."""

    VERSION = "1.0"

    def __init__(self, audit_log_path: Optional[Path] = None) -> None:
        self.audit = MerkleLog(audit_log_path)

    # -- keys ----------------------------------------------------------- #
    def generate_keypair(self) -> tuple[bytes, bytes]:
        """Generate an Ed25519 keypair. Returns ``(private_pem, public_pem)``."""
        priv = Ed25519PrivateKey.generate()
        priv_pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_pem = priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return priv_pem, pub_pem

    # -- hashing -------------------------------------------------------- #
    def compute_canonical_hash(self, tool_descriptor: dict) -> str:
        """SHA-256 of canonicalized (sorted-key) JSON. Any change ⇒ new hash."""
        return hashlib.sha256(_canonical_json(tool_descriptor)).hexdigest()

    # -- signing -------------------------------------------------------- #
    def sign_tool(self, tool_descriptor: dict, private_key_pem: bytes,
                  publisher: str = "unknown") -> dict:
        """Sign a tool descriptor; returns a distributable signed bundle.

        The signature is over the canonical JSON of the entire bundle *except*
        the signature field, so tampering with the tool, its hash, the publisher
        or the timestamp all invalidate it.
        """
        priv = serialization.load_pem_private_key(private_key_pem, password=None)
        if not isinstance(priv, Ed25519PrivateKey):
            raise TypeError("private key is not an Ed25519 key")
        bundle = {
            "tool": tool_descriptor,
            "sha256": self.compute_canonical_hash(tool_descriptor),
            "publisher": publisher,
            "signed_at": _now_iso(),
            "version": self.VERSION,
        }
        sig = priv.sign(_canonical_json(bundle))
        bundle["signature"] = base64.b64encode(sig).decode("ascii")
        return bundle

    # -- verification --------------------------------------------------- #
    def verify_tool(self, signed_bundle: dict, public_key_pem: bytes,
                    approved_hash: Optional[str] = None,
                    publisher_known: bool = True,
                    publisher_trust: Optional[str] = None,
                    log: bool = True) -> VerificationResult:
        """Verify a signed bundle. Decision is PASS / REJECT / ALERT.

        REJECT when: the publisher is unknown, the Ed25519 signature is invalid
        (the description was modified in transit), or the SHA-256 no longer
        matches the approved baseline (rug-pull). ALERT when everything verifies
        but the publisher is only ``UNTRUSTED``.
        """
        tool = signed_bundle.get("tool", {})
        recomputed = self.compute_canonical_hash(tool)

        # Ed25519 signature over the bundle-minus-signature.
        unsigned = {k: v for k, v in signed_bundle.items() if k != "signature"}
        sig_valid = False
        try:
            pub = serialization.load_pem_public_key(public_key_pem)
            if isinstance(pub, Ed25519PublicKey) and "signature" in signed_bundle:
                pub.verify(base64.b64decode(signed_bundle["signature"]), _canonical_json(unsigned))
                sig_valid = True
        except (InvalidSignature, Exception):  # noqa: BLE001
            sig_valid = False

        hash_matches: Optional[bool] = None
        rug = False
        if approved_hash is not None:
            hash_matches = recomputed == approved_hash
            rug = not hash_matches

        if not publisher_known:
            decision, reason = "REJECT", "unknown publisher (not in trust registry)"
        elif not sig_valid:
            decision, reason = "REJECT", "invalid signature — tool description was modified in transit"
        elif rug:
            decision, reason = "REJECT", "rug-pull detected — hash changed since approval baseline"
        elif (publisher_trust or "").upper() == "UNTRUSTED":
            decision, reason = "ALERT", "signature valid but publisher is UNTRUSTED"
        else:
            decision, reason = "PASS", "tool is authentic and unmodified"

        if log:
            self.audit.add(tool.get("name", "<unnamed>"), recomputed,
                           decision if decision != "ALERT" else "ALERT")

        return VerificationResult(
            sig_valid=sig_valid, hash_matches=hash_matches, rug_pull_detected=rug,
            publisher_known=publisher_known, decision=decision, reason=reason,
            recomputed_hash=recomputed,
        )

    # -- convenience ---------------------------------------------------- #
    def add_merkle_entry(self, tool_name: str, tool_hash: str, decision: str) -> str:
        """Add a tamper-evident audit log entry; returns the entry hash."""
        return self.audit.add(tool_name, tool_hash, decision)
