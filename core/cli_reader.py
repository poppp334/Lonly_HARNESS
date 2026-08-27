#!/usr/bin/env python3
"""core/cli_reader.py — Interactive Line Editing, History & Autocompletion for LONLY.

Enforces:
- Full Left/Right/Up/Down arrow key navigation by design.
- Command history persistence across sessions (~/.lonly/history).
- Tab autocompletion for slash commands and dynamic session IDs.
- Zero external dependencies (uses standard library `readline`).
"""
from __future__ import annotations

import atexit
import os
import sys
from pathlib import Path
from typing import Any, Callable, Optional


CLI_COMMANDS = [
    "/help",
    "/scope",
    "/scope add",
    "/scope list",
    "/scope reset",
    "/session",
    "/session list",
    "/session new",
    "/session load",
    "/report",
    "/doctor",
    "/clear",
    "exit",
    "quit",
    "help",
    "clear",
]


def create_completer(session_manager_getter: Optional[Callable[[], Any]] = None) -> Callable[[str, int], Optional[str]]:
    """Create a tab completer supporting static commands and dynamic session IDs."""
    def completer(text: str, state: int) -> Optional[str]:
        options = list(CLI_COMMANDS)

        # Dynamic session ID completion for `/session load `
        if text.startswith("/session load ") or text.startswith("session load "):
            if session_manager_getter:
                sm = session_manager_getter()
                if sm:
                    prefix = text.split(maxsplit=2)[0] + " load "
                    cand_id = text[len(prefix):]
                    for s in sm.list_sessions():
                        sid = s.get("session_id", "")
                        if sid.startswith(cand_id):
                            options.append(f"{prefix}{sid}")

        matches = [c for c in options if c.startswith(text)]
        if state < len(matches):
            return matches[state]
        return None

    return completer


def setup_cli_readline(
    history_file: Optional[Path] = None,
    session_manager_getter: Optional[Callable[[], Any]] = None,
) -> bool:
    """Initialize readline for full arrow key navigation, line editing, history, and tab completion."""
    try:
        import readline

        # 1. Configure Tab completion
        readline.set_completer_delims(" \t\n")
        readline.set_completer(create_completer(session_manager_getter))
        readline.parse_and_bind("tab: complete")

        # 2. Configure persistent history file
        if history_file is None:
            hist_dir = Path.home() / ".lonly"
            hist_dir.mkdir(parents=True, exist_ok=True)
            history_file = hist_dir / "history"

        if history_file.exists():
            try:
                readline.read_history_file(str(history_file))
            except Exception:
                pass

        readline.set_history_length(1000)

        def save_history():
            try:
                readline.write_history_file(str(history_file))
            except Exception:
                pass

        atexit.register(save_history)
        return True
    except ImportError:
        return False
