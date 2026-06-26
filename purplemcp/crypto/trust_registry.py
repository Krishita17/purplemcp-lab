"""MCP Trust Registry — publisher authentication.

In production this would be an X.509 certificate chain verified against a root
CA. Here it is a JSON-backed registry of known publishers, each mapped to a
public key and a trust level. The registry answers two questions for CryptoMCP:
*is this publisher known?* and *does the presented public key match the one we
have on file?* (a key swap is as bad as an unknown publisher).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Optional


class TrustRegistry:
    """Registry of trusted MCP tool publishers."""

    TRUST_LEVELS = {
        "VERIFIED": "Publisher identity verified, SOC 2 audited",
        "COMMUNITY": "Open source, community reviewed",
        "UNTRUSTED": "Unknown publisher — use with caution",
        "REVOKED": "Publisher certificate revoked",
    }

    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = Path(path) if path else None
        self._pubs: dict[str, dict] = {}
        if self.path and self.path.exists():
            try:
                self._pubs = json.loads(self.path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self._pubs = {}

    # -- persistence ---------------------------------------------------- #
    def _save(self) -> None:
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self._pubs, indent=2), encoding="utf-8")

    @staticmethod
    def _cert_id(public_key_pem: bytes) -> str:
        return "cert_" + hashlib.sha256(public_key_pem).hexdigest()[:16]

    # -- API ------------------------------------------------------------ #
    def register_publisher(self, name: str, public_key_pem: bytes,
                           trust_level: str = "COMMUNITY") -> str:
        """Register a publisher; returns a deterministic certificate id."""
        if trust_level not in self.TRUST_LEVELS:
            raise ValueError(f"unknown trust level {trust_level!r}")
        cert_id = self._cert_id(public_key_pem)
        self._pubs[name] = {
            "cert_id": cert_id,
            "public_key_pem": public_key_pem.decode("ascii"),
            "trust_level": trust_level,
        }
        self._save()
        return cert_id

    def verify_publisher(self, publisher_name: str, public_key_pem: bytes) -> bool:
        """True iff the publisher is known, not revoked, and the key matches."""
        rec = self._pubs.get(publisher_name)
        if not rec or rec["trust_level"] == "REVOKED":
            return False
        return rec["public_key_pem"] == public_key_pem.decode("ascii")

    def is_known(self, publisher_name: str) -> bool:
        rec = self._pubs.get(publisher_name)
        return bool(rec) and rec["trust_level"] != "REVOKED"

    def trust_level(self, publisher_name: str) -> str:
        rec = self._pubs.get(publisher_name)
        return rec["trust_level"] if rec else "UNTRUSTED"

    def public_key(self, publisher_name: str) -> Optional[bytes]:
        rec = self._pubs.get(publisher_name)
        return rec["public_key_pem"].encode("ascii") if rec else None

    def list_publishers(self) -> list[dict]:
        return [
            {"name": name, "cert_id": rec["cert_id"], "trust_level": rec["trust_level"]}
            for name, rec in self._pubs.items()
        ]

    def revoke_publisher(self, publisher_name: str) -> bool:
        rec = self._pubs.get(publisher_name)
        if not rec:
            return False
        rec["trust_level"] = "REVOKED"
        self._save()
        return True
