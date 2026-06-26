"""CryptoMCP — cryptographic integrity layer for MCP tool descriptions.

Ed25519 signing/verification, SHA-256 canonical hashing, a Merkle-chained audit
log (:mod:`~purplemcp.crypto.cryptomcp`) and a publisher trust registry
(:mod:`~purplemcp.crypto.trust_registry`).
"""

from .cryptomcp import CryptoMCP, MerkleLog, VerificationResult
from .trust_registry import TrustRegistry

__all__ = ["CryptoMCP", "MerkleLog", "VerificationResult", "TrustRegistry"]
