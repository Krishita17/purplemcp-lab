"""Regenerate the GUI screenshots used in the README/docs.

Renders each page of the desktop app offscreen at a consistent size and saves it
to docs/images/gui/. Reproducible:

    QT_QPA_PLATFORM=offscreen python scripts/gen_screenshots.py

Needs the GUI extra (PySide6). Several pages are *driven* so the shots show real
content: the scanner runs a scan, the explorer connects to the calculator, the
Attack Lab arms + runs a live exploit, the Defense Lab arms + verifies (exploited
vs. blocked), and the Chat Playground holds a real tool-calling conversation with
the local model (needs Ollama running with a tool-capable model, e.g. qwen2.5).
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "docs" / "images" / "gui"
SIZE = (1480, 940)

PAGE_SHOTS = {
    "dashboard": "1_dashboard.png",
    "explorer": "2_explorer.png",
    "chat": "3_chat.png",
    "scanner": "4_scanner.png",
    "attacks": "5_attacks.png",
    "defense": "6_defense.png",
    "models": "7_models.png",
    "servers": "8_servers.png",
    "research": "9_research.png",
    "learn": "10_learn.png",
}


def pump(app: QApplication, seconds: float) -> None:
    end = time.time() + seconds
    while time.time() < end:
        app.processEvents()
        time.sleep(0.01)


def pump_until(app: QApplication, cond, timeout: float = 8.0) -> bool:
    end = time.time() + timeout
    while time.time() < end and not cond():
        app.processEvents()
        time.sleep(0.02)
    pump(app, 0.3)
    try:
        return bool(cond())
    except Exception:  # noqa: BLE001
        return False


def _select_in_list(page, attack_id: str) -> None:
    """Select a module by id in a lab page's left list."""
    lst = page._list
    for i in range(lst.count()):
        meta = lst.item(i).data(Qt.UserRole)
        if meta is not None and getattr(meta, "id", None) == attack_id:
            lst.setCurrentRow(i)
            return


def drive_attacks(app, page) -> None:
    _select_in_list(page, "command-injection")
    pump(app, 0.3)
    page._arm.setChecked(True)
    pump(app, 0.2)
    page._run_btn.click()
    pump_until(app, lambda: page._console.toPlainText().strip() != "", 30)
    pump(app, 0.5)


def drive_defense(app, page) -> None:
    _select_in_list(page, "command-injection")
    pump(app, 0.3)
    page._arm.setChecked(True)
    pump(app, 0.2)
    page._verify_btn.click()
    pump_until(app, lambda: page._red._verdict.text().lower() != "idle", 30)
    pump(app, 0.6)


def drive_chat(app, page) -> None:
    # calculator is pre-ticked; start a session and ask a tool-using question.
    page._toggle_session()
    if not pump_until(app, lambda: page._session is not None and page._input.isEnabled(), 30):
        return
    page._input.setText("What is 19% of 4200 plus the square root of 144? Use the tools.")
    page._send()
    pump_until(
        app,
        lambda: len(page._tool_cards) > 0 or page._feed.count() > 4,
        75,
    )
    pump(app, 1.0)


def main() -> int:
    from purplemcp.gui.app import MainWindow
    from purplemcp.gui.async_bridge import AsyncLoop
    from purplemcp.gui.theme import stylesheet

    OUT.mkdir(parents=True, exist_ok=True)
    app = QApplication.instance() or QApplication(sys.argv)
    app.setStyleSheet(stylesheet())
    window = MainWindow(AsyncLoop())
    window.resize(*SIZE)
    window.show()
    pump(app, 0.8)

    for key, filename in PAGE_SHOTS.items():
        window._go_and_select(key)
        page = window._pages[key]
        pump(app, 0.5)

        try:
            if key == "scanner" and hasattr(page, "_scan_btn"):
                page._scan_btn.click()
                pump_until(app, lambda: page._findings_box.count() > 0, 10)
            elif key == "explorer" and hasattr(page, "_connect_btn"):
                page._connect_btn.click()
                pump_until(app, lambda: page._tool_list.count() > 0, 10)
            elif key == "attacks":
                drive_attacks(app, page)
            elif key == "defense":
                drive_defense(app, page)
            elif key == "chat":
                drive_chat(app, page)
            else:
                pump(app, 2.0)  # let async-loading pages (e.g. Models) populate
        except Exception as exc:  # noqa: BLE001 - best-effort; still grab
            print(f"  ! {key}: {exc}")

        window.grab().save(str(OUT / filename))
        print(f"  saved {filename}")

    # command palette (a separate popup widget)
    window._open_palette()
    pump(app, 0.4)
    window._palette.grab().save(str(OUT / "11_palette.png"))
    print("  saved 11_palette.png")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
