#!/usr/bin/env python3
"""core/tool_context.py — per-call execution context for brokered tool invocations.

Carries the operator-approval decision from the agent gate down to the broker
without threading an `approved` argument through every tool wrapper. The
context is task-local (contextvars), so concurrent tool calls cannot leak one
call's approval into another.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from typing import Iterator

_APPROVED: ContextVar[bool] = ContextVar("lonly_tool_approved", default=False)


def current_approval() -> bool:
    """Return the approval decision for the tool call currently executing."""
    return _APPROVED.get()


@contextmanager
def approval_context(approved: bool) -> Iterator[None]:
    """Bind an approval decision to the current execution context."""
    token = _APPROVED.set(bool(approved))
    try:
        yield
    finally:
        _APPROVED.reset(token)
