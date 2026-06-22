"""Crisp, tintable SVG line icons rendered to :class:`QIcon` / :class:`QPixmap`.

Each entry is the *inner* markup of a 24x24 stroke icon using ``currentColor``;
:func:`icon` swaps in a concrete colour and renders at 2x for retina sharpness.
Keeping the icons inline means no asset files to ship or find at runtime.
"""

from __future__ import annotations

from functools import lru_cache

from PySide6.QtCore import QByteArray, QRectF, Qt
from PySide6.QtGui import QIcon, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer

from .theme import PALETTE

# 24x24 viewBox, 2px round strokes, no fill — a coherent line-icon set.
_ICONS: dict[str, str] = {
    "dashboard": '<rect x="3" y="3" width="7" height="9" rx="1.5"/>'
                 '<rect x="14" y="3" width="7" height="5" rx="1.5"/>'
                 '<rect x="14" y="12" width="7" height="9" rx="1.5"/>'
                 '<rect x="3" y="16" width="7" height="5" rx="1.5"/>',
    "tools":     '<path d="M14.5 5.5a3.5 3.5 0 0 0-4.9 4.2L4 15.3V20h4.7l5.6-5.6a3.5 3.5 0 0 0 4.2-4.9l-2.4 2.4-2.1-2.1z"/>',
    "chat":      '<path d="M4 5h16v11H8l-4 4z" stroke-linejoin="round"/>'
                 '<path d="M8 9h8M8 12h5"/>',
    "scanner":   '<path d="M12 3l7 3v5c0 4.5-3 7.6-7 9-4-1.4-7-4.5-7-9V6z" stroke-linejoin="round"/>'
                 '<path d="M9 12l2 2 4-4"/>',
    "arena":     '<path d="M14.5 4H20v5.5L9.5 20H4v-5.5z" stroke-linejoin="round"/>'
                 '<path d="M14.5 4 20 9.5M7 13l4 4"/>',
    "server":    '<rect x="3" y="4" width="18" height="7" rx="2"/>'
                 '<rect x="3" y="13" width="18" height="7" rx="2"/>'
                 '<path d="M7 7.5h.01M7 16.5h.01"/>',
    "cpu":       '<rect x="6" y="6" width="12" height="12" rx="2"/>'
                 '<path d="M9 1.5v3M15 1.5v3M9 19.5v3M15 19.5v3M1.5 9h3M1.5 15h3M19.5 9h3M19.5 15h3"/>',
    "play":      '<path d="M7 4.5v15l13-7.5z" stroke-linejoin="round"/>',
    "refresh":   '<path d="M20 11a8 8 0 1 0-1.5 5"/><path d="M20 4v6h-6"/>',
    "send":      '<path d="M4 12l16-8-6 16-3-7z" stroke-linejoin="round"/>',
    "lock":      '<rect x="5" y="10" width="14" height="10" rx="2"/>'
                 '<path d="M8 10V7a4 4 0 0 1 8 0v3"/>',
    "check":     '<path d="M5 12l5 5 9-11"/>',
    "x":         '<path d="M6 6l12 12M18 6 6 18"/>',
    "alert":     '<path d="M12 3l9 16H3z" stroke-linejoin="round"/><path d="M12 10v4M12 17h.01"/>',
    "search":    '<circle cx="11" cy="11" r="6"/><path d="M16 16l4 4"/>',
    "plus":      '<path d="M12 5v14M5 12h14"/>',
    "folder":    '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" stroke-linejoin="round"/>',
    "bolt":      '<path d="M13 2 4 14h7l-1 8 9-12h-7z" stroke-linejoin="round"/>',
    "skull":     '<path d="M12 3a8 8 0 0 0-5 14v2a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1v-2a8 8 0 0 0-5-14z" stroke-linejoin="round"/>'
                 '<circle cx="9" cy="12" r="1.4"/><circle cx="15" cy="12" r="1.4"/>',
    "chart":     '<path d="M3 21h18"/><rect x="5" y="11" width="3.2" height="7" rx="1"/>'
                 '<rect x="10.4" y="6" width="3.2" height="12" rx="1"/>'
                 '<rect x="15.8" y="9" width="3.2" height="9" rx="1"/>',
    "book":      '<path d="M6 4h12a1 1 0 0 1 1 1v15H7a2 2 0 0 0-2 2V6a2 2 0 0 1 2-2z" '
                 'stroke-linejoin="round"/><path d="M9 4v16"/>',
    "command":   '<path d="M9 6a3 3 0 1 0-3 3h12a3 3 0 1 0-3-3v12a3 3 0 1 0 3-3H6a3 3 0 1 0 3 3z"/>',
    "gear":      '<circle cx="12" cy="12" r="3"/>'
                 '<path d="M12 2.5v2.2M12 19.3v2.2M2.5 12h2.2M19.3 12h2.2'
                 'M5.2 5.2l1.6 1.6M17.2 17.2l1.6 1.6M18.8 5.2l-1.6 1.6M6.8 17.2l-1.6 1.6"/>',
}


def _svg(name: str, color: str, width: float = 2.0) -> bytes:
    body = _ICONS.get(name, "")
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" '
        f'fill="none" stroke="{color}" stroke-width="{width}" '
        f'stroke-linecap="round">{body}</svg>'
    ).encode("utf-8")


@lru_cache(maxsize=512)
def pixmap(name: str, color: str = "#ffffff", size: int = 22, width: float = 2.0) -> QPixmap:
    renderer = QSvgRenderer(QByteArray(_svg(name, color, width)))
    scale = 2  # render at 2x for crispness on hi-dpi
    pm = QPixmap(size * scale, size * scale)
    pm.setDevicePixelRatio(scale)
    pm.fill(Qt.transparent)
    painter = QPainter(pm)
    painter.setRenderHint(QPainter.Antialiasing)
    renderer.render(painter, QRectF(0, 0, size, size))
    painter.end()
    return pm


def icon(name: str, color: str | None = None, size: int = 22, width: float = 2.0) -> QIcon:
    return QIcon(pixmap(name, color or PALETTE["text_dim"], size, width))
