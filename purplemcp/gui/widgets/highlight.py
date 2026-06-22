"""A lightweight Python syntax highlighter (no external dependency).

Good enough to make the Defense Lab's guardrail source readable: keywords,
builtins, decorators, numbers, single-line and triple-quoted strings, and
comments. Triple-quoted docstrings are handled across block boundaries.
"""

from __future__ import annotations

import keyword

from PySide6.QtCore import QRegularExpression
from PySide6.QtGui import QColor, QFont, QSyntaxHighlighter, QTextCharFormat

from ..theme import PALETTE

_TRIPLE = '"""'


def _fmt(color: str, *, bold: bool = False, italic: bool = False) -> QTextCharFormat:
    fmt = QTextCharFormat()
    fmt.setForeground(QColor(color))
    if bold:
        fmt.setFontWeight(QFont.Bold)
    if italic:
        fmt.setFontItalic(True)
    return fmt


class PythonHighlighter(QSyntaxHighlighter):
    def __init__(self, document) -> None:
        super().__init__(document)
        self._rules: list[tuple[QRegularExpression, QTextCharFormat]] = []

        kw = _fmt(PALETTE["purple_hi"], bold=True)
        for word in keyword.kwlist:
            self._rules.append((QRegularExpression(rf"\b{word}\b"), kw))

        builtin = _fmt(PALETTE["cyan"])
        for word in ("self", "cls", "True", "False", "None", "len", "range", "set",
                     "dict", "list", "str", "int", "float", "bytes", "isinstance"):
            self._rules.append((QRegularExpression(rf"\b{word}\b"), builtin))

        self._rules.append((QRegularExpression(r"@[\w.]+"), _fmt(PALETTE["amber"])))
        self._rules.append((QRegularExpression(r"\b[0-9][0-9_.]*\b"), _fmt(PALETTE["amber"])))
        self._rules.append((QRegularExpression(r"\bdef\s+(\w+)"), _fmt(PALETTE["blue"], bold=True)))
        self._rules.append((QRegularExpression(r"\bclass\s+(\w+)"), _fmt(PALETTE["blue"], bold=True)))

        self._string = _fmt(PALETTE["green"])
        self._comment = _fmt(PALETTE["text_faint"], italic=True)
        self._str_rules = [
            QRegularExpression(r"'[^'\\]*(\\.[^'\\]*)*'"),
            QRegularExpression(r'"[^"\\]*(\\.[^"\\]*)*"'),
        ]

    def highlightBlock(self, text: str) -> None:
        for rx, fmt in self._rules:
            it = rx.globalMatch(text)
            while it.hasNext():
                m = it.next()
                self.setFormat(m.capturedStart(), m.capturedLength(), fmt)

        for rx in self._str_rules:
            it = rx.globalMatch(text)
            while it.hasNext():
                m = it.next()
                self.setFormat(m.capturedStart(), m.capturedLength(), self._string)

        hash_at = text.find("#")
        if hash_at >= 0:
            self.setFormat(hash_at, len(text) - hash_at, self._comment)

        # Triple-quoted strings (docstrings), spanning blocks.
        self.setCurrentBlockState(0)
        if self.previousBlockState() == 1:
            start, add = 0, 0
        else:
            start, add = text.find(_TRIPLE), 3
        while start >= 0:
            end = text.find(_TRIPLE, start + add)
            if end >= 0:
                length = end - start + 3  # include the closing delimiter
            else:
                self.setCurrentBlockState(1)
                length = len(text) - start
            self.setFormat(start, length, self._string)
            nxt = start + length
            start = text.find(_TRIPLE, nxt)
            add = 3
