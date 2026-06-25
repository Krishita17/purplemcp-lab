"""PurpleMCP guardrails — the reusable hardening library.

These are the production-quality primitives the **defense** pillar is built on.
Import them into any MCP server you write:

    from purplemcp.guardrails import safe_resolve, safe_get, safe_run

Each module documents the exact attack it neutralizes.
"""

from .approval import ApprovalDenied, auto_allow, auto_deny, cli_confirm, require
from .argv import safe_argv
from .authz import (
    AuthorizationError,
    assert_assignable,
    assert_owner,
    can_access,
    require_scope,
)
from .csvsafe import escape_formula, is_formula
from .limits import cap_text, within_limit
from .descriptions import (
    ToolPinner,
    find_injection,
    has_hidden_unicode,
    sanitize_description,
    tool_fingerprint,
)
from .exec import CommandNotAllowed
from .exec import run as safe_run
from .framing import frame_untrusted, sanitize_output, strip_control
from .headers import HeaderInjectionError, safe_header_value
from .jwtsafe import JWTError, sign_jwt, verify_jwt
from .net import SSRFError, assert_url_allowed, safe_get
from .redirects import OpenRedirectError, safe_redirect
from .safexml import XMLSecurityError, safe_parse_xml
from .saferegex import literal_search
from .paths import PathTraversalError, safe_resolve
from .ratelimit import RateLimiter, RateLimitExceeded
from .safe_eval import UnsafeExpression, safe_eval
from .registry import (
    ToolShadowingError,
    assert_no_shadowing,
    base_name,
    enforce_allowlist,
    find_collisions,
)
from .secrets import find_secrets, scrub
from .serialization import UnsafeDeserialization, looks_like_pickle, safe_loads
from .sqlsafe import SQLIdentifierError, like_escape, safe_identifier
from .templating import TemplateInjectionError, safe_format
from .tokens import constant_time_compare, new_hex_token, new_token

__all__ = [
    # paths
    "safe_resolve",
    "PathTraversalError",
    # net
    "safe_get",
    "assert_url_allowed",
    "SSRFError",
    # exec
    "safe_run",
    "CommandNotAllowed",
    # descriptions
    "sanitize_description",
    "find_injection",
    "has_hidden_unicode",
    "tool_fingerprint",
    "ToolPinner",
    # approval
    "require",
    "cli_confirm",
    "auto_allow",
    "auto_deny",
    "ApprovalDenied",
    # secrets
    "scrub",
    "find_secrets",
    # ratelimit
    "RateLimiter",
    "RateLimitExceeded",
    # serialization
    "safe_loads",
    "looks_like_pickle",
    "UnsafeDeserialization",
    # templating
    "safe_format",
    "TemplateInjectionError",
    # sqlsafe
    "safe_identifier",
    "like_escape",
    "SQLIdentifierError",
    # registry (tool shadowing)
    "find_collisions",
    "enforce_allowlist",
    "assert_no_shadowing",
    "base_name",
    "ToolShadowingError",
    # authz (broken access control + mass assignment)
    "assert_owner",
    "can_access",
    "require_scope",
    "assert_assignable",
    "AuthorizationError",
    # safe_eval (eval / expression injection)
    "safe_eval",
    "UnsafeExpression",
    # csvsafe (CSV / formula injection)
    "escape_formula",
    "is_formula",
    # limits (unbounded output / context flooding)
    "cap_text",
    "within_limit",
    # argv (argument / flag injection)
    "safe_argv",
    # tokens (weak randomness)
    "new_token",
    "new_hex_token",
    "constant_time_compare",
    # framing (output / log injection)
    "strip_control",
    "sanitize_output",
    "frame_untrusted",
    # jwtsafe (insecure JWT verification)
    "verify_jwt",
    "sign_jwt",
    "JWTError",
    # safexml (XML external entity / XXE)
    "safe_parse_xml",
    "XMLSecurityError",
    # saferegex (regex injection)
    "literal_search",
    # redirects (open redirect)
    "safe_redirect",
    "OpenRedirectError",
    # headers (CRLF / HTTP header injection)
    "safe_header_value",
    "HeaderInjectionError",
]
