"""Red vs blue, side by side.

Runs the same malicious input against a vulnerable server and its hardened twin
so you can see the leak and the fix back to back. Requires the lab flag because
it launches the vulnerable servers.

    export PURPLEMCP_LAB_ENABLED="i-understand-this-is-a-lab"
    python defense/compare.py                # every case
    python defense/compare.py ping           # just the case whose tool/title matches
    python defense/compare.py "sql injection"
"""

import asyncio
import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "attacks"))  # for _lab.safety

from _lab.safety import require_lab  # noqa: E402

require_lab("defense comparison")

import base64  # noqa: E402
import pickle  # noqa: E402

from purplemcp.config import ServerSpec  # noqa: E402
from purplemcp.host import MCPHost  # noqa: E402


class _PickleRCEProof:
    """Unpickling runs eval('PWN'+str(6*7)); harmless, but proves code executed."""

    def __reduce__(self):
        return (eval, ("'PWN' + str(6 * 7)",))


_PICKLE_BLOB = base64.b64encode(pickle.dumps(_PickleRCEProof())).decode()


def _zip_blob(entries: dict) -> str:
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    return base64.b64encode(buf.getvalue()).decode()


_SLIP_BLOB = _zip_blob({"../19_ZIPSLIP_PROOF.txt": "PWNED-BY-ZIP-SLIP"})

CASES = [
    (
        "command injection",
        "ping",
        {"host": "127.0.0.1; echo PWNED_BY_$(whoami)"},
        REPO / "attacks/03_command_injection/vulnerable_server.py",
        REPO / "defense/hardened_servers/safe_nettools.py",
    ),
    (
        "path traversal",
        "read_doc",
        {"path": "/etc/hosts"},
        REPO / "attacks/04_path_traversal/vulnerable_server.py",
        REPO / "defense/hardened_servers/safe_docreader.py",
    ),
    (
        "sql injection",
        "search_notes",
        {"query": "%' OR 1=1 -- "},
        REPO / "attacks/10_sql_injection/vulnerable_server.py",
        REPO / "defense/hardened_servers/safe_notes_search.py",
    ),
    (
        "template injection",
        "render_welcome",
        {"template": "{app.__init__.__globals__[SECRET_TOKEN]}", "username": "guest"},
        REPO / "attacks/11_template_injection/vulnerable_server.py",
        REPO / "defense/hardened_servers/safe_templater.py",
    ),
    (
        "insecure deserialization",
        "load_session",
        {"blob": _PICKLE_BLOB},
        REPO / "attacks/13_insecure_deserialization/vulnerable_server.py",
        REPO / "defense/hardened_servers/safe_state_loader.py",
    ),
    (
        "broken access control",
        "get_record",
        {"record_id": 2},
        REPO / "attacks/14_broken_access_control/vulnerable_server.py",
        REPO / "defense/hardened_servers/safe_records.py",
    ),
    (
        "unrestricted file write",
        "save_note",
        {"path": "../15_ESCAPED_PROOF.txt", "content": "PWNED-WRITE-ESCAPE"},
        REPO / "attacks/15_unrestricted_file_write/vulnerable_server.py",
        REPO / "defense/hardened_servers/safe_writer.py",
    ),
    (
        "weak randomness",
        "issue_reset_token",
        {"user": "victim@corp.example"},
        REPO / "attacks/16_weak_randomness/vulnerable_server.py",
        REPO / "defense/hardened_servers/safe_token_issuer.py",
    ),
    (
        "output / log injection",
        "record_event",
        {"message": "ok\n[SECURITY] AUTH_BYPASS_GRANTED\x1b[2J"},
        REPO / "attacks/17_output_injection/vulnerable_server.py",
        REPO / "defense/hardened_servers/safe_logger.py",
    ),
    (
        "eval injection",
        "calculate",
        {"expr": "'PWN' + str(6 * 7)"},
        REPO / "attacks/18_eval_injection/vulnerable_server.py",
        REPO / "defense/hardened_servers/safe_calculator.py",
    ),
    (
        "zip slip",
        "unpack",
        {"zip_b64": _SLIP_BLOB},
        REPO / "attacks/19_zip_slip/vulnerable_server.py",
        REPO / "defense/hardened_servers/safe_unpacker.py",
    ),
    (
        "mass assignment",
        "update_profile",
        {"updates": {"display_name": "x", "role": "admin", "is_admin": True}},
        REPO / "attacks/20_mass_assignment/vulnerable_server.py",
        REPO / "defense/hardened_servers/safe_profile.py",
    ),
    (
        "csv / formula injection",
        "export_row",
        {"name": "Alice", "note": "=DANGER_FORMULA(2+3)"},
        REPO / "attacks/21_csv_injection/vulnerable_server.py",
        REPO / "defense/hardened_servers/safe_csv.py",
    ),
]


def _spec(path: pathlib.Path) -> ServerSpec:
    return ServerSpec(name="srv", transport="stdio", command=sys.executable, args=[str(path)])


async def _run(path: pathlib.Path, tool: str, args: dict) -> str:
    async with MCPHost([_spec(path)]) as host:
        return await host.call_tool(tool, args)


def _show(text: str, head: int = 5, tail: int = 4) -> str:
    lines = text.splitlines()
    if len(lines) <= head + tail:
        chosen = lines
    else:
        chosen = lines[:head] + ["..."] + lines[-tail:]
    return "\n".join("      " + line for line in chosen)


def _selected() -> list:
    """Optionally filter CASES by a CLI query matching the title or tool name."""
    query = " ".join(sys.argv[1:]).strip().lower()
    if not query:
        return CASES
    hits = [c for c in CASES if query in c[0].lower() or query in c[1].lower()]
    if not hits:
        known = ", ".join(sorted(c[1] for c in CASES))
        print(f"no case matches {query!r}. tools: {known}")
    return hits


async def main() -> None:
    for title, tool, args, vuln, hardened in _selected():
        print("=" * 72)
        print(f"  {title}  —  {tool}({args})")
        print("=" * 72)
        v = await _run(vuln, tool, args)
        h = await _run(hardened, tool, args)
        print("\n  [RED] vulnerable server:")
        print(_show(v))
        print("\n  [BLUE] hardened twin:")
        print(_show(h))
        print()


if __name__ == "__main__":
    asyncio.run(main())
