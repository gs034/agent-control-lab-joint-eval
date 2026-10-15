# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Make text derived from fixtures safe to write to a terminal.

Fixture strings (and error messages that quote them) are authored data. A
raw ESC, CSI, OSC or other control character in them could move the
cursor, rewrite earlier lines, retitle the window, or plant a fake
``ok: true`` line. Every C0 control except tab, DEL, and every C1 control
is written as a visible ``\\xNN`` escape instead. Newline is escaped too
unless the caller keeps it, so one message stays on one line.
"""

from __future__ import annotations


def _is_control(code: int) -> bool:
    return code < 0x20 or code == 0x7F or 0x80 <= code <= 0x9F


def terminal_safe(text: str, *, keep_newlines: bool = False) -> str:
    """``text`` with control characters (ESC included) replaced by ``\\xNN``."""
    out: list[str] = []
    for char in text:
        code = ord(char)
        if char == "\t" or (keep_newlines and char == "\n") or not _is_control(code):
            out.append(char)
        else:
            out.append(f"\\x{code:02x}")
    return "".join(out)
