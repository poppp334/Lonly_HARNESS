#!/usr/bin/env python3
"""core/session.py — Session State & Context Window Management for LONLY v2.

Enforces:
- Structured session persistence to JSONL (similar to agy / opencode / claude-code).
- Rolling context window compaction and persistent findings across sessions.
- Multi-session workspace switching and history recall.
- Zero overlapping or colliding job state across isolated sessions.
"""
from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass
class SessionMessage:
    """Single message entry in the persistent session ledger."""
    role: str  # "user", "assistant", "system", "tool", "observation"
    content: str
    timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%S"))
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SessionState:
    """Persistent session state holding conversation history and context compaction."""
    session_id: str
    title: str = "New Pentest Session"
    created_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%S"))
    updated_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%S"))
    active_target: str = ""
    context_summary: str = ""
    messages: list[SessionMessage] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "title": self.title,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "active_target": self.active_target,
            "context_summary": self.context_summary,
            "messages": [m.to_dict() for m in self.messages],
        }


class SessionManager:
    """Coordinates local session workspaces, JSONL event logging, and context compaction."""

    DEFAULT_BASE_DIR = Path.home() / ".lonly" / "sessions"

    def __init__(self, base_dir: Optional[Path | str] = None):
        self.base_dir = Path(base_dir) if base_dir else self.DEFAULT_BASE_DIR
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.active_session: Optional[SessionState] = None

    def create_session(self, title: str = "Pentest Session", session_id: Optional[str] = None) -> SessionState:
        """Create a new persistent session workspace with clean, isolated state."""
        s_id = session_id or f"sess_{time.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
        session = SessionState(session_id=s_id, title=title)
        self.active_session = session
        self.save_session(session)
        return session

    def get_or_create_active_session(self) -> SessionState:
        """Return the current active session or create a default one."""
        if self.active_session is None:
            sessions = self.list_sessions()
            if sessions:
                latest_id = sessions[0]["session_id"]
                loaded = self.load_session(latest_id)
                if loaded:
                    self.active_session = loaded
                    return loaded
            self.active_session = self.create_session("Default Session")
        return self.active_session

    def get_session_dir(self, session_id: str) -> Path:
        s_dir = self.base_dir / session_id
        s_dir.mkdir(parents=True, exist_ok=True)
        return s_dir

    def get_session_log_file(self, session_id: Optional[str] = None) -> Path:
        """Return path to the session_log.jsonl for the specified or active session."""
        s_id = session_id or (self.active_session.session_id if self.active_session else "default")
        return self.get_session_dir(s_id) / "session_log.jsonl"

    def log_event(self, event: dict, session_id: Optional[str] = None) -> None:
        """Log a structured event directly into the active session log with isolation."""
        log_file = self.get_session_log_file(session_id)
        with open(log_file, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, ensure_ascii=False) + "\n")

    def get_tool_calls(self, session_id: Optional[str] = None) -> list[dict]:
        """Retrieve all tool call records strictly for the specified session."""
        log_file = self.get_session_log_file(session_id)
        if not log_file.exists():
            return []
        calls = []
        with open(log_file, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        entry = json.loads(line)
                        if entry.get("type") == "tool_call":
                            calls.append(entry)
                    except Exception:
                        pass
        return calls

    def get_seen_calls(self, session_id: Optional[str] = None) -> set[tuple[str, tuple]]:
        """Return set of (tool_name, sorted_args_tuple) for duplicate prevention in active session."""
        tool_calls = self.get_tool_calls(session_id)
        seen = set()
        for call in tool_calls:
            tn = call.get("tool_name")
            ta = call.get("tool_args", {})
            if isinstance(ta, dict):
                seen.add((tn, tuple(sorted(ta.items()))))
        return seen

    def clear_active_session_logs(self) -> None:
        """Purge logs for current active session without affecting other sessions."""
        if self.active_session:
            log_file = self.get_session_log_file(self.active_session.session_id)
            if log_file.exists():
                try:
                    log_file.unlink()
                except OSError:
                    pass
            self.active_session.messages.clear()
            self.save_session(self.active_session)

    def save_session(self, session: SessionState) -> None:
        """Persist session state and transcripts to JSONL and metadata JSON."""
        session.updated_at = time.strftime("%Y-%m-%dT%H:%M:%S")
        s_dir = self.get_session_dir(session.session_id)

        meta_file = s_dir / "meta.json"
        with open(meta_file, "w", encoding="utf-8") as fh:
            meta = {
                "session_id": session.session_id,
                "title": session.title,
                "created_at": session.created_at,
                "updated_at": session.updated_at,
                "active_target": session.active_target,
                "context_summary": session.context_summary,
                "message_count": len(session.messages),
            }
            json.dump(meta, fh, ensure_ascii=False, indent=2)

        transcript_file = s_dir / "transcript.jsonl"
        with open(transcript_file, "w", encoding="utf-8") as fh:
            for msg in session.messages:
                fh.write(json.dumps(msg.to_dict(), ensure_ascii=False) + "\n")

    def load_session(self, session_id: str) -> Optional[SessionState]:
        """Load session state from disk."""
        s_dir = self.base_dir / session_id
        meta_file = s_dir / "meta.json"
        transcript_file = s_dir / "transcript.jsonl"

        if not meta_file.exists() or not transcript_file.exists():
            return None

        with open(meta_file, "r", encoding="utf-8") as fh:
            meta = json.load(fh)

        messages = []
        with open(transcript_file, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    d = json.loads(line)
                    messages.append(SessionMessage(
                        role=d.get("role", "user"),
                        content=d.get("content", ""),
                        timestamp=d.get("timestamp", ""),
                        metadata=d.get("metadata", {}),
                    ))

        session = SessionState(
            session_id=meta.get("session_id", session_id),
            title=meta.get("title", "Loaded Session"),
            created_at=meta.get("created_at", ""),
            updated_at=meta.get("updated_at", ""),
            active_target=meta.get("active_target", ""),
            context_summary=meta.get("context_summary", ""),
            messages=messages,
        )
        self.active_session = session
        return session

    def list_sessions(self) -> list[dict]:
        """List all available stored sessions sorted by last updated."""
        results = []
        if not self.base_dir.exists():
            return results
        for entry in self.base_dir.iterdir():
            if entry.is_dir():
                meta_file = entry / "meta.json"
                if meta_file.exists():
                    try:
                        with open(meta_file, "r", encoding="utf-8") as fh:
                            results.append(json.load(fh))
                    except Exception:
                        pass
        results.sort(key=lambda x: x.get("updated_at", ""), reverse=True)
        return results

    def append_message(self, session: SessionState, role: str, content: str, metadata: Optional[dict] = None) -> SessionMessage:
        """Add a message to the active session and persist immediately."""
        msg = SessionMessage(role=role, content=content, metadata=metadata or {})
        session.messages.append(msg)
        self.save_session(session)
        return msg

    def get_compacted_messages(self, session: SessionState, max_window: int = 20) -> list[SessionMessage]:
        """Return sliding window with summary context header if history exceeds window."""
        if len(session.messages) <= max_window:
            return session.messages

        older = session.messages[:-max_window]
        recent = session.messages[-max_window:]

        if not session.context_summary and older:
            summary_points = []
            for m in older:
                if m.role == "user":
                    summary_points.append(f"User asked: {m.content[:100]}")
                elif m.role == "assistant" and "Final Answer:" in m.content:
                    summary_points.append(f"Agent concluded: {m.content[:150]}")
            session.context_summary = "Prior session summary: " + " | ".join(summary_points[-3:])

        return recent
