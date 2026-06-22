"""The PurpleMCP look & feel — a light, summery *sorbet* security console.

Everything visual flows from :data:`PALETTE`. :func:`stylesheet` turns it into the
Qt Style Sheet applied to the whole app, and the semantic colour helpers below are
reused by custom-painted widgets (severity bars, badges, the arena verdict).

The palette is a light **peach · mint · lilac** sorbet: cream backgrounds, white
cards, and pastel accents tuned just dark enough to stay readable as text on white.
"""

from __future__ import annotations

# --------------------------------------------------------------------------- #
#  palette  —  Sorbet (peach · mint · lilac), a light summery theme
# --------------------------------------------------------------------------- #
PALETTE: dict[str, str] = {
    # warm cream backgrounds + crisp white cards
    "bg":          "#fff4ef",
    "content":     "#fffaf8",
    "sidebar":     "#ffe9e0",
    "surface":     "#ffffff",
    "surface_hi":  "#fbeef3",
    "surface_2":   "#fdf3ef",
    # lines (soft warm + lilac)
    "border":      "#f2dcd4",
    "border_hi":   "#e7c4d8",
    # text (dark slate for contrast on the light base)
    "text":        "#4f4860",
    "text_dim":    "#867e96",
    "text_faint":  "#ada4bc",
    # brand -> lilac
    "purple":      "#a37fda",
    "purple_hi":   "#b98fe8",
    "violet":      "#b08ee0",
    "indigo":      "#8aa1ec",
    # semantic (pastel-leaning but readable on white)
    "red":         "#e76a82",
    "amber":       "#dd9a2b",
    "cyan":        "#2ba6c0",
    "blue":        "#4ea3da",
    "green":       "#3fb38d",
}

# severity -> colour key (used by the scanner + arena)
SEVERITY_COLORS: dict[str, str] = {
    "HIGH":   PALETTE["red"],
    "MEDIUM": PALETTE["amber"],
    "LOW":    PALETTE["cyan"],
    "INFO":   PALETTE["text_faint"],
}

# red team / blue team accents
RED_TEAM = PALETTE["red"]
BLUE_TEAM = PALETTE["blue"]

MONO = '"SF Mono", "Menlo", "JetBrains Mono", "Consolas", monospace'


def rgba(hex_color: str, alpha: float) -> str:
    """``#rrggbb`` + alpha (0..1) → a Qt ``rgba(r, g, b, a)`` string.

    Use this instead of appending two hex digits to a colour: Qt parses 8-digit
    hex as ``#AARRGGBB`` (alpha first), so ``"#8b5cf6" + "22"`` silently becomes a
    completely different colour (a green, in that case).
    """
    h = hex_color.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return f"rgba({r}, {g}, {b}, {alpha})"


def stylesheet() -> str:
    """The global Qt Style Sheet, interpolated from :data:`PALETTE`."""
    p = PALETTE
    return f"""
    * {{
        outline: 0;
    }}
    QWidget {{
        background: transparent;
        color: {p['text']};
        font-size: 13px;
    }}
    QMainWindow, #Root {{
        background: {p['bg']};
    }}
    QToolTip {{
        background: {p['surface_hi']};
        color: {p['text']};
        border: 1px solid {p['border_hi']};
        border-radius: 6px;
        padding: 5px 8px;
    }}

    /* ---- content scroll surface ---- */
    #ContentArea {{
        background: {p['content']};
        border-top-left-radius: 18px;
        border-bottom-left-radius: 18px;
        border-left: 1px solid {p['border']};
    }}

    /* ---- sidebar ---- */
    #Sidebar {{
        background: {p['sidebar']};
    }}
    #BrandTitle {{
        font-size: 17px;
        font-weight: 800;
        color: {p['text']};
    }}
    #BrandSub {{
        color: {p['text_faint']};
        font-size: 10px;
        font-weight: 600;
        letter-spacing: 2px;
    }}
    QPushButton#NavButton {{
        background: transparent;
        color: {p['text_dim']};
        border: none;
        border-left: 3px solid transparent;
        border-radius: 10px;
        padding: 10px 12px 10px 13px;
        text-align: left;
        font-size: 13px;
        font-weight: 600;
    }}
    QPushButton#NavButton:hover {{
        background: {p['surface']};
        color: {p['text']};
    }}
    QPushButton#NavButton:checked {{
        background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
            stop:0 rgba(163,127,218,0.30), stop:1 rgba(138,161,236,0.10));
        border-left: 3px solid {p['purple']};
        color: {p['text']};
    }}
    #NavGroupLabel {{
        color: {p['text_faint']};
        font-size: 10px;
        font-weight: 700;
        letter-spacing: 1.5px;
    }}

    /* ---- headings & text ---- */
    #PageTitle   {{ font-size: 25px; font-weight: 800; color: {p['text']}; letter-spacing: -0.3px; }}
    #PageSub     {{ font-size: 13px; color: {p['text_dim']}; }}
    #SectionTitle{{ font-size: 14px; font-weight: 700; color: {p['text']}; letter-spacing: 0.2px; }}
    #Muted       {{ color: {p['text_dim']}; }}
    #Faint       {{ color: {p['text_faint']}; font-size: 12px; }}
    .Mono, #Mono {{ font-family: {MONO}; }}

    /* ---- cards ---- */
    #Card {{
        background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
            stop:0 {p['surface_hi']}, stop:1 {p['surface']});
        border: 1px solid {p['border']};
        border-radius: 14px;
    }}
    #CardFlat {{
        background: {p['surface_2']};
        border: 1px solid {p['border']};
        border-radius: 12px;
    }}
    #CardTitle {{ font-size: 13px; font-weight: 700; color: {p['text']}; letter-spacing: 0.2px; }}

    /* ---- buttons ---- */
    QPushButton {{
        background: {p['surface_hi']};
        color: {p['text']};
        border: 1px solid {p['border_hi']};
        border-radius: 9px;
        padding: 8px 16px;
        font-weight: 600;
    }}
    QPushButton:hover {{ background: {p['border']}; border-color: {p['violet']}; }}
    QPushButton:pressed {{ background: {p['surface_2']}; }}
    QPushButton:disabled {{ color: {p['text_faint']}; border-color: {p['border']}; background: {p['surface_2']}; }}

    QPushButton[variant="primary"] {{
        background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
            stop:0 {p['violet']}, stop:1 {p['purple']});
        border: none;
        color: white;
        padding: 9px 18px;
    }}
    QPushButton[variant="primary"]:hover {{
        background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
            stop:0 {p['indigo']}, stop:1 {p['purple_hi']});
    }}
    QPushButton[variant="primary"]:pressed {{
        background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
            stop:0 {p['violet']}, stop:1 {p['violet']});
    }}
    QPushButton[variant="primary"]:disabled {{
        background: {p['surface_2']}; color: {p['text_faint']};
    }}
    QPushButton[variant="danger"] {{
        background: rgba(244,63,94,0.14); color: {p['red']};
        border: 1px solid rgba(244,63,94,0.45);
    }}
    QPushButton[variant="danger"]:hover {{ background: rgba(244,63,94,0.24); }}
    QPushButton[variant="blue"] {{
        background: rgba(59,130,246,0.14); color: {p['blue']};
        border: 1px solid rgba(59,130,246,0.45);
    }}
    QPushButton[variant="blue"]:hover {{ background: rgba(59,130,246,0.24); }}
    QPushButton[variant="ghost"] {{
        background: transparent; border: 1px solid {p['border']};
        color: {p['text_dim']};
    }}
    QPushButton[variant="ghost"]:hover {{ color: {p['text']}; border-color: {p['border_hi']}; }}

    /* ---- inputs ---- */
    QLineEdit, QPlainTextEdit, QTextEdit, QSpinBox {{
        background: {p['surface_2']};
        border: 1px solid {p['border']};
        border-radius: 9px;
        padding: 8px 10px;
        color: {p['text']};
        selection-background-color: {p['violet']};
    }}
    QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus, QSpinBox:focus {{
        border: 1px solid {p['violet']};
    }}
    QLineEdit::placeholder {{ color: {p['text_faint']}; }}

    /* ---- combo box ---- */
    QComboBox {{
        background: {p['surface_2']};
        border: 1px solid {p['border']};
        border-radius: 9px;
        padding: 7px 12px;
        color: {p['text']};
        min-height: 18px;
    }}
    QComboBox:hover {{ border-color: {p['border_hi']}; }}
    QComboBox:focus {{ border-color: {p['violet']}; }}
    QComboBox::drop-down {{ border: none; width: 22px; }}
    QComboBox::down-arrow {{
        image: none;
        border-left: 4px solid transparent;
        border-right: 4px solid transparent;
        border-top: 5px solid {p['text_dim']};
        margin-right: 8px;
    }}
    QComboBox QAbstractItemView {{
        background: {p['surface_hi']};
        border: 1px solid {p['border_hi']};
        border-radius: 8px;
        padding: 4px;
        selection-background-color: {p['violet']};
        outline: 0;
    }}

    /* ---- checkbox ---- */
    QCheckBox {{ spacing: 8px; color: {p['text_dim']}; }}
    QCheckBox::indicator {{
        width: 17px; height: 17px; border-radius: 5px;
        border: 1px solid {p['border_hi']}; background: {p['surface_2']};
    }}
    QCheckBox::indicator:checked {{
        background: {p['purple']}; border-color: {p['purple']};
    }}

    /* ---- scrollbars ---- */
    QScrollArea, QScrollArea > QWidget > QWidget {{ background: transparent; border: none; }}
    QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
    QScrollBar::handle:vertical {{
        background: {p['border_hi']}; border-radius: 5px; min-height: 30px;
    }}
    QScrollBar::handle:vertical:hover {{ background: {p['violet']}; }}
    QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
    QScrollBar::handle:horizontal {{
        background: {p['border_hi']}; border-radius: 5px; min-width: 30px;
    }}
    QScrollBar::handle:horizontal:hover {{ background: {p['violet']}; }}
    QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
    QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}

    /* ---- splitter ---- */
    QSplitter::handle {{ background: transparent; }}
    QSplitter::handle:hover {{ background: {p['border']}; }}
    """
