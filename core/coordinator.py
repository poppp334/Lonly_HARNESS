#!/usr/bin/env python3
"""core/coordinator.py — Hexagonal ReAct Execution Coordinator for LONLY v2.

Encapsulates the state machine for ReAct agent turns:
- Prompt composition & dynamic state injection (task tree, findings log, target context)
- Inbound LLM generation via LLMPort protocol
- Inbound operator approval via ApprovalPort protocol
- Outbound tool execution via ToolCallExecutor & ToolInvokerPort protocol
- Outbound evidence persistence via EvidenceGraph
- Outbound structured logging via get_logger("lonly.coordinator")
- Claim verification, fabrication checks, overclaim interception, and privesc specialist delegation
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from typing import Optional, Sequence

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from core.config import get_config, get_logger
from core.evidence import ClaimVerifier, fence_untrusted
from core.guardrails import (
    CONFIRM_REQUIRED_TOOLS,
    RISK_CHECKPOINT_THRESHOLD,
    RISK_DESCRIPTIONS,
    RISK_POINTS,
    extract_targets_from_args,
)
from core.parser import (
    check_overclaim,
    clean_answer_text,
    extract_explicit_targets_from_text,
    extract_final_answer,
    find_fabricated_tool_mentions,
    is_placeholder_answer,
    parse_react_response,
    sanitize_hallucinated_targets,
)
from core.ports import ApprovalPort, LLMPort
from core.session_context import SessionContext
from core.state import Finding, PHASE_MODEL_MAP
from core.tool_dispatch import evaluate_tool_call
from core.vault import DEFAULT_VAULT
from tools import run_argv, tool_map
from tools.base import clean_target

logger = get_logger("lonly.coordinator")

SYSTEM_PROMPT = """You are LONLY, an elite, policy-governed autonomous penetration testing and cybersecurity AI assistant on Kali Linux powered by __MODEL_NAME__.

## OPERATING MODES:

### MODE 1: CONVERSATION & Q&A (NO TOOLS)
- When the operator greets you (e.g. "Hi", "Hello"), asks general questions, asks about your identity, model, or capabilities, or discusses assessment strategy, reply DIRECTLY in clear, natural, professional Markdown without invoking tools.
- If the operator asks whether you are ready without providing a target, confirm readiness and ask for the target host or URL.
- Do NOT invoke tools or output 'Action:' when having a conversation or answering general questions.

### MODE 2: TACTICAL SECURITY ASSESSMENT (ReAct TOOLS)
- When the operator gives an objective or assessment task against a target, use the ReAct format:

Thought: (your reasoning and tactical plan)
Action: (tool_name from the list below)
Action Input: (valid JSON parameters)

- When you receive Observations and have enough information to satisfy the objective, respond with:

Final Answer: <your concise technical summary here>

## CRITICAL RULES
1. **HONESTY**: NEVER mention a tool in your Final Answer unless you actually called it and received an Observation for it. Fabrication will be flagged.
2. **FAILURES & PIVOTS**: If a tool errors or returns empty/trivial output, state that clearly and pivot to a logical alternative (e.g., if a port scan times out, probe standard web ports directly with whatweb or curl). Do not invent findings.
3. **DO NOT OVERCLAIM**: Report only what the raw output explicitly shows. If a tool reports nothing found, explicitly report no findings.
4. **ONE ACTION AT A TIME**: Output exactly ONE Thought, Action, and Action Input per turn, then wait for Observation.
5. **ALWAYS USE JSON**: Action Input must always be valid, parseable JSON on a single line or standard multiline JSON.
6. **NO HALLUCINATED PLACEHOLDERS**: Never use dummy target placeholders (e.g., target.com, domain.com). Use the user's explicit target.

## AVAILABLE TOOLS:
- nmap_security_scan: {"target": "10.0.0.5", "scan_type": "-sS", "ports": "top-100", "timing": 4}
- rustscan_port_scan: {"target": "10.0.0.5", "ports": "1-65535", "batch_size": 4500}
- masscan_port_scan: {"target": "10.0.0.5", "ports": "1-10000", "rate": 1000}
- whatweb_web_fingerprint: {"target": "http://10.0.0.5"}
- gobuster_directory_scan: {"target_url": "http://10.0.0.5", "wordlist": "common"}
- ffuf_web_fuzz: {"url": "http://10.0.0.5/FUZZ", "wordlist": "common"}
- nikto_web_scan: {"target": "http://10.0.0.5"} — DANGEROUS (permission)
- sqlmap_vulnerability_assessment: {"url": "http://10.0.0.5/page.php?id=1", "risk": 1, "level": 1} — DANGEROUS (permission)
- wpscan_wordpress_audit: {"url": "http://10.0.0.5"}
- enum4linux_smb_audit: {"target_ip": "10.0.0.5"} — DANGEROUS (permission)
- crackmapexec: {"target": "10.0.0.5", "protocol": "smb", "username": "", "password": "", "exec_cmd": ""}
- ldap_search_enumeration: {"target_ip": "10.0.0.5", "base_dn": "DC=corp,DC=local", "search_filter": "(objectClass=*)"}
- kerbrute_active_directory_assessment: {"domain": "corp.local", "dc_ip": "10.0.0.5", "mode": "userenum", "wordlist": "/usr/share/wordlists/seclists/Usernames/top-usernames-short.txt"}
- hydra_brute_force: {"target": "10.0.0.5", "service": "ssh", "username": "admin", "password": "password123"} — CONFIRMATION REQUIRED
- searchsploit_exploit_lookup: {"query": "Apache 2.4.49"}
- metasploit_auxiliary_scanner: {"module": "scanner/smb/smb_version", "rhosts": "10.0.0.5"} — CONFIRMATION REQUIRED
- linpeas_privilege_escalation_scan: {"script_path": "/usr/share/peass-ng/linux/linpeas.sh"}
- reverse_shell_listener: {"port": 4444, "listen_timeout": 60}
- impacket_tool_execute: {"tool_name": "secretsdump.py", "target": "10.0.0.5", "connection_string": "corp/admin:Password123", "extra_args": ""}
- curl_web_request: {"url": "http://10.0.0.5", "method": "GET", "data": "", "headers": ""}
- shell_exec: {"cmd": "whoami", "timeout": 60}
- cve_lookup: {"query": "CVE-2021-44228"}
- bloodhound_analyze: {"zip_path": "/tmp/bloodhound_data.zip"}
- rag_query: {"query": "how to bypass UAC"}

## FINAL ANSWER FORMAT
- One‑sentence summary.
- Bulleted findings with evidence (e.g., "Port 445 open (SMB)").
- If failed/empty: state that and suggest next step.
- Do not list tools you didn't use.
"""

TOOL_KIND_MAP = {
    "nmap_security_scan": "open_port",
    "rustscan_port_scan": "open_port",
    "masscan_port_scan": "open_port",
    "whatweb_web_fingerprint": "service",
    "gobuster_directory_scan": "service",
    "ffuf_web_fuzz": "service",
    "ldap_search_enumeration": "service",
    "bloodhound_analyze": "service",
    "linpeas_privilege_escalation_scan": "service",
    "nikto_web_scan": "vuln",
    "sqlmap_vulnerability_assessment": "vuln",
    "wpscan_wordpress_audit": "vuln",
    "kerbrute_active_directory_assessment": "vuln",
    "searchsploit_exploit_lookup": "vuln",
    "metasploit_auxiliary_scanner": "vuln",
    "cve_lookup": "vuln",
    "impacket_tool_execute": "vuln",
    "hydra_brute_force": "credential",
    "crackmapexec": "credential",
}

PHASE_ADVANCE_RULES = {
    "recon": {"open_port"},
    "enumerate": {"service"},
    "vuln_check": {"vuln"},
    "privesc": set(),
    "report": set(),
}

MAX_CHAT_HISTORY = 20
SESSION_LOG_FILE = "session_log.jsonl"


def _trim_history(history: list, limit: int = MAX_CHAT_HISTORY) -> list:
    """Bound a chat history in place, keeping only the most recent messages."""
    if limit > 0 and len(history) > limit:
        del history[:-limit]
    return history


def compute_carryover_decay(current_task_number: int, event: dict) -> tuple[int, str]:
    """Calculate decayed points and description for a carryover risk event."""
    task_age = current_task_number - event["task_number"]
    pts = event["points"]
    if task_age == 1:
        return pts, f"task {event['task_number']}: {event['event_type']} = {pts} full"
    elif task_age == 2:
        half = pts // 2
        return half, f"task {event['task_number']}: {event['event_type']} = {half} (half of {pts})"
    return 0, ""


def get_carryover_risk(current_task_number: int, event_log: list) -> int:
    """Sum carryover risk from past events with bounded decay."""
    total = 0
    remaining = []
    for event in event_log:
        task_age = current_task_number - event["task_number"]
        pts, _ = compute_carryover_decay(current_task_number, event)
        if task_age in (1, 2) or task_age <= 0:
            total += pts
            remaining.append(event)
    event_log.clear()
    event_log.extend(remaining)
    return total


def build_checkpoint_header(
    ctx: SessionContext,
    current_task_number: int,
    risk_score: int,
    threshold: int,
    actually_invoked: list[dict],
) -> str:
    """Format a detailed checkpoint header with risk breakdown and in-task tool summary."""
    carryover_parts = []
    carryover_total = 0
    for event in ctx.carryover_event_log:
        pts, desc = compute_carryover_decay(current_task_number, event)
        if pts > 0 and desc:
            carryover_total += pts
            carryover_parts.append(desc)

    carryover_str = "; ".join(carryover_parts) if carryover_parts else "none"

    type_counts: dict[str, int] = {}
    in_task_total = 0
    for e in ctx.in_task_risk_events:
        t = e["type"]
        type_counts[t] = type_counts.get(t, 0) + 1
        in_task_total += e["points"]
    in_task_parts = [f"{count} {t.replace('_', ' ')}" for t, count in sorted(type_counts.items())]
    in_task_str = " + ".join(in_task_parts) if in_task_parts else "none"

    tool_names = list(dict.fromkeys(t["tool_name"] for t in actually_invoked))
    tool_list = ", ".join(tool_names) if tool_names else "(none yet)"

    return (
        f"=== Task {current_task_number} — Checkpoint (risk {risk_score}/{threshold}) ===\n"
        f"  Carryover: {carryover_total} pts [{carryover_str}]\n"
        f"  In-task:   {in_task_total} pts [{in_task_str}]\n"
        f"  In-task tools: {tool_list}\n"
        f"  Total:     {risk_score} >= {threshold} — paused for operator review."
    )


def summarize_findings(history: Sequence[object]) -> str:
    """Extract latest observations and summarize concisely."""
    observations = []
    for msg in history[-10:]:
        if isinstance(msg, AIMessage) and "Observation:" in msg.content:
            observations.append(msg.content[:200])
    if observations:
        return "พบข้อมูล " + "; ".join(observations[:3])
    return "ไม่พบข้อมูลที่ชัดเจน"


def _record_finding(ctx: SessionContext, tool_name: str, tool_args: dict, result: str, raw_result: str) -> None:
    kind = TOOL_KIND_MAP.get(tool_name)
    if not kind:
        return
    targets = [t for t in extract_targets_from_args(tool_args) if t]
    ctx.findings_log.add(Finding(
        kind=kind,
        target=", ".join(targets) if targets else "local",
        detail=(result or raw_result)[:200].replace("\n", " "),
        evidence=f"{tool_name} {tool_args} -> {raw_result[:200]}",
        tool=tool_name,
    ))
    rule = PHASE_ADVANCE_RULES.get(ctx.task_tree.current)
    if rule and kind in rule:
        ctx.task_tree.advance()


def _log_jsonl(entry: dict, ctx: Optional[SessionContext] = None) -> None:
    try:
        raw_json = json.dumps(entry, ensure_ascii=False)
        redacted_json = DEFAULT_VAULT.redact(raw_json)
        if ctx and getattr(ctx, "session", None):
            sess = ctx.session
            from core.session import SessionManager
            sm = SessionManager()
            sess_log = sm.get_session_log_file(sess.session_id)
            with open(sess_log, "a", encoding="utf-8") as f:
                f.write(redacted_json + "\n")
        if SESSION_LOG_FILE:
            with open(SESSION_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(redacted_json + "\n")
    except Exception as e:
        logger.warning("Failed to write session log: %s", e)


def build_tool_history_block(ctx: Optional[SessionContext] = None) -> str:
    entries = []
    target_file = None
    if ctx and getattr(ctx, "session", None):
        from core.session import SessionManager
        sm = SessionManager()
        sess_log = sm.get_session_log_file(ctx.session.session_id)
        if sess_log.exists():
            target_file = sess_log

    if target_file is None and os.path.exists(SESSION_LOG_FILE):
        target_file = SESSION_LOG_FILE

    if target_file:
        try:
            with open(target_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        if entry.get("type") == "tool_call":
                            entries.append(entry)
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            pass

    if not entries:
        return "=== Tool Call History (this session) ===\n(No tool calls recorded yet in this session.)"

    lines = ["=== Tool Call History (this session) ==="]
    for i, entry in enumerate(entries, 1):
        t_name = entry.get("tool_name", "?")
        t_args = entry.get("tool_args", {})
        raw_res = entry.get("raw_result", "")
        appr = entry.get("approved", "")
        lines.append(f"\n[{i}] Tool: {t_name}")
        lines.append(f"    Args: {json.dumps(t_args, ensure_ascii=False)}")
        if appr:
            lines.append(f"    Approval: {appr}")
        lines.append(f"    Raw output:\n{raw_res}")

    return "\n".join(lines)


def _run_privesc_specialist(ctx: Optional[SessionContext] = None) -> Optional[dict]:
    """Delegate privesc sub-goal to specialist model if context is configured."""
    if ctx is None:
        try:
            import pentest_agent as pa
            ctx = pa._default_context()
        except Exception:
            return None
    ssh_target = os.environ.get("LONLY_PRIVESC_SSH", "")
    privesc_user = os.environ.get("LONLY_PRIVESC_USER", "")
    if not ssh_target or not privesc_user:
        return None
    try:
        models_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
        if models_dir not in sys.path:
            sys.path.insert(0, models_dir)
        from privesc_protocol import PrivescSpecialist, ToolResult  # type: ignore
    except Exception as exc:
        logger.warning("Privesc specialist import failed: %s", exc)
        return None

    def _got_root(out: str) -> bool:
        return "uid=0(" in out or "euid=0" in out or "root@" in out

    class _Backend:
        def exec_command(self, command: str) -> ToolResult:
            argv = [
                "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=accept-new",
                "-o", "ConnectTimeout=10",
                ssh_target,
                command,
            ]
            pa_mod = sys.modules.get("pentest_agent")
            runner = getattr(pa_mod, "run_argv", run_argv) if pa_mod else run_argv
            out = runner("ssh", argv, target=ssh_target, capability="privesc_specialist_ssh", timeout=60, max_output=2000)
            return ToolResult(_got_root(out), out)

        def test_credentials(self, user: str, password: str) -> ToolResult:
            return ToolResult(False, "credential testing not wired in v1 backend")

    pa_mod = sys.modules.get("pentest_agent")
    phase_map = getattr(pa_mod, "PHASE_MODEL_MAP", PHASE_MODEL_MAP) if pa_mod else PHASE_MODEL_MAP
    spec = PrivescSpecialist(
        _Backend(),
        model=phase_map.get("privesc", "privesc-llm-rl:4b"),
        user=privesc_user,
        password=os.environ.get("LONLY_PRIVESC_PASSWORD", ""),
        max_turns=int(os.environ.get("LONLY_PRIVESC_MAX_TURNS", "20")),
        trajectory_path=os.path.join(ctx.findings_log.run_dir, "privesc_trajectories.jsonl"),
    )
    logger.info("Privesc phase: delegating to specialist %s on %s", spec.model, ssh_target)
    print(f"[*] Privesc phase: delegating to specialist {spec.model} on {ssh_target}")
    return spec.run()


class ReActCoordinator:
    """Hexagonal ReAct Orchestrator decoupling agent state machine from CLI frontend."""

    def __init__(
        self,
        context: SessionContext,
        llm_port: LLMPort,
        approval_port: ApprovalPort,
        config=None,
    ) -> None:
        self.ctx = context
        self.llm = llm_port
        self.approval = approval_port
        self.cfg = config or get_config()

    def run_turn(self, user_input: str, max_steps: int = 8) -> str:
        """Execute a single multi-step conversational or ReAct tool turn."""
        ctx = self.ctx
        active_session = ctx.session
        from core.session import SessionManager
        session_manager = SessionManager()
        session_manager.append_message(active_session, "user", user_input)

        explicit_targets = extract_explicit_targets_from_text(user_input)
        current_turn_target = explicit_targets[0] if explicit_targets else None
        scope_non_default = [t for t in ctx.scope if t not in ("127.0.0.1", "localhost", "::1")]
        effective_target = current_turn_target or active_session.active_target or (scope_non_default[0] if scope_non_default else None)

        if explicit_targets:
            active_session.active_target = explicit_targets[0]
            session_manager.save_session(active_session)
        elif effective_target and not active_session.active_target:
            active_session.active_target = effective_target
            session_manager.save_session(active_session)

        explicit_target = effective_target
        generalist_model = self.cfg.model_name
        sys_prompt_content = SYSTEM_PROMPT.replace("__MODEL_NAME__", generalist_model)

        messages = [SystemMessage(content=sys_prompt_content)]
        for msg in ctx.chat_history:
            if isinstance(msg, SystemMessage):
                continue
            messages.append(msg)
        messages.append(HumanMessage(content=user_input))
        ctx.chat_history.append(HumanMessage(content=user_input))

        ctx.task_number += 1
        current_task_number = ctx.task_number

        sess_log = session_manager.get_session_log_file(active_session.session_id)
        if not sess_log.exists() and ctx.seen_calls:
            ctx.seen_calls.clear()

        _log_jsonl({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "type": "turn_input",
            "content": user_input,
            "task_number": current_task_number,
        }, ctx=ctx)

        step = 0
        risk_score = get_carryover_risk(current_task_number, ctx.carryover_event_log)
        ctx.in_task_risk_events.clear()
        actually_invoked_tools: list[dict] = []
        privesc_attempted = False
        placeholder_retry_count = 0
        mode1_target_retry_count = 0
        _trim_history(ctx.chat_history)

        while step < max_steps:
            step += 1
            target_context = f"\n[TARGET CONTEXT] Active assessment target: {effective_target}. Always use this exact target in tool arguments." if effective_target else ""
            messages[0] = SystemMessage(
                content=sys_prompt_content + "\n\n"
                + target_context + "\n"
                + ctx.task_tree.prompt_block() + "\n"
                + ctx.findings_log.prompt_block()
            )

            # Privesc specialist delegation
            if ctx.task_tree.current == "privesc" and not privesc_attempted:
                privesc_attempted = True
                psr = _run_privesc_specialist(ctx)
                if psr is not None:
                    _log_jsonl({
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                        "type": "privesc_specialist",
                        **{k: v for k, v in psr.items() if k != "messages"},
                    }, ctx=ctx)
                    if psr.get("success"):
                        ctx.findings_log.add(Finding(
                            kind="vuln",
                            target=os.environ.get("LONLY_PRIVESC_SSH", "target"),
                            detail=f"root obtained via privesc specialist in {psr['turns']} turns",
                            evidence=f"specialist run: {psr['reason']}",
                            tool="privesc_specialist",
                        ))
                    note = (
                        f"[PRIVESC SPECIALIST] success={psr['success']} turns={psr['turns']} "
                        f"reason={psr['reason']} tool_calls={psr['tool_calls']}"
                    )
                    messages.append(AIMessage(content=note))
                    ctx.chat_history.append(AIMessage(content=note))
                    ctx.task_tree.advance()
                    continue

            threshold = getattr(sys.modules.get("pentest_agent"), "RISK_CHECKPOINT_THRESHOLD", RISK_CHECKPOINT_THRESHOLD)
            logger.info("LONLY planning turn step=%d/%d (task=%d, risk=%d/%d)", step, max_steps, current_task_number, risk_score, threshold)
            print("[*] LONLY is analyzing and planning...", flush=True)

            response = self.llm.invoke(messages)
            response_text = getattr(response, "content", str(response))
            messages.append(AIMessage(content=response_text))
            ctx.chat_history.append(AIMessage(content=response_text))

            tool_name, tool_args = parse_react_response(response_text)

            # Action execution path
            if tool_name and tool_name in tool_map:
                if tool_args and explicit_target:
                    tool_args = sanitize_hallucinated_targets(tool_args, explicit_target)

                evaluation = evaluate_tool_call(
                    tool_name,
                    tool_args,
                    scope=ctx.scope_port,
                    seen_calls=ctx.seen_calls,
                    risk_score=risk_score,
                    threshold=threshold,
                )

                if evaluation.checkpoint_required:
                    logger.warning("Risk checkpoint triggered at score %d >= %d", risk_score, threshold)
                    print("\n" + build_checkpoint_header(
                        ctx, current_task_number, risk_score, threshold, actually_invoked_tools
                    ))
                    print("\n" + build_tool_history_block(ctx))
                    choice = self.approval.request("\n[c]ontinue / [s]top task / [r]edirect: ").lower()
                    risk_score = 0
                    ctx.in_task_risk_events.clear()
                    if choice in ("s", "stop"):
                        return "[CHECKPOINT STOP] Task stopped at user request."
                    if choice in ("r", "redirect"):
                        ctx.task_number += 1
                        return "[CHECKPOINT REDIRECT] Task redirected at user request. Enter a new objective."
                    continue

                if evaluation.is_dangerous:
                    warning = f"!!! Tool {tool_name} is intrusive. Ask user permission before using."
                    messages.append(AIMessage(content=warning))
                    ctx.chat_history.append(AIMessage(content=warning))
                    risk_score += evaluation.risk_delta
                    ctx.in_task_risk_events.append({"type": "dangerous_tool_blocked", "points": evaluation.risk_delta})
                    logger.warning("Dangerous tool %s blocked: risk delta +%d -> %d", tool_name, evaluation.risk_delta, risk_score)
                    print(f"  [risk: {risk_score}/{threshold}]")
                    continue

                if evaluation.requires_confirmation:
                    user_prompt = (
                        f"\n[CONFIRM] LLM wants to run {tool_name} with: {tool_args}\n"
                        f"This tool can {RISK_DESCRIPTIONS[tool_name]}. Allow? [y/n]: "
                    )
                    answer = self.approval.request(user_prompt).lower()
                    operator_approved = answer in ("y", "yes")
                    risk_score += evaluation.risk_delta
                    ctx.in_task_risk_events.append({"type": "confirm_required_tool", "points": evaluation.risk_delta})
                    logger.info("Confirmation gate for %s: operator_approved=%s (risk=%d/%d)", tool_name, operator_approved, risk_score, threshold)
                    print(f"  [risk: {risk_score}/{threshold}]")
                    if not operator_approved:
                        denial = f"!!! User denied permission for {tool_name} with args {tool_args}. Choose a different approach or report what you have so far."
                        messages.append(AIMessage(content=denial))
                        ctx.chat_history.append(AIMessage(content=denial))
                        continue
                else:
                    operator_approved = False

                if evaluation.is_duplicate:
                    duplicate_msg = f"!!! You already ran {tool_name} with these exact arguments. Please choose a different tool or provide Final Answer."
                    messages.append(AIMessage(content=duplicate_msg))
                    ctx.chat_history.append(AIMessage(content=duplicate_msg))
                    logger.info("Duplicate tool call intercepted: %s", evaluation.call_key)
                    continue
                ctx.seen_calls.add(evaluation.call_key)

                # Scope allowlist gate
                if evaluation.out_of_scope:
                    targets_str = ", ".join(evaluation.out_of_scope)
                    user_allowed = False
                    try:
                        scope_prompt = (
                            f"\n[SCOPE GATE] Tool '{tool_name}' requests target: {targets_str}\n"
                            f"Target is not in the authorized scope (current: {ctx.scope or 'loopback only'}).\n"
                            f"Authorize adding '{targets_str}' to scope for this session? [y/n]: "
                        )
                        ans = self.approval.request(scope_prompt).lower()
                        if ans in ("y", "yes"):
                            for t in evaluation.out_of_scope:
                                clean_t = clean_target(t)
                                if clean_t and clean_t not in ctx.scope:
                                    ctx.scope.append(clean_t)
                                if active_session:
                                    active_session.active_target = clean_t
                                    session_manager.save_session(active_session)
                            logger.info("Scope extended to: %s", ctx.scope)
                            print(f"[+] Scope updated! Authorized: {ctx.scope}")
                            user_allowed = True
                    except (EOFError, Exception) as exc:
                        logger.warning("Scope prompt failed: %s", exc)
                        user_allowed = False

                    if not user_allowed:
                        denial = (
                            f"[SCOPE BLOCKED] Tool {tool_name} would touch out-of-scope target(s): "
                            f"{targets_str}. In-scope: {ctx.scope or 'loopback only'}. "
                            f"Choose an in-scope target or ask the user to extend the authorized scope."
                        )
                        _log_jsonl({
                            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                            "type": "scope_block",
                            "tool_name": tool_name,
                            "tool_args": tool_args,
                            "blocked_targets": list(evaluation.out_of_scope),
                            "content": denial,
                            "safety_passed": False,
                            "task_number": current_task_number,
                        }, ctx=ctx)
                        messages.append(AIMessage(content=denial))
                        ctx.chat_history.append(AIMessage(content=denial))
                        logger.warning("Scope blocked target(s): %s", targets_str)
                        print(f"  [scope-block] {targets_str}")
                        return f"[-] Scope Gate: Target '{targets_str}' is outside authorized scope (In-scope: {ctx.scope or 'loopback only'}). Authorization was not granted."

                logger.info("Dispatching tool %s with args: %s", tool_name, tool_args)
                print(f"\n[+] LONLY กำลังรัน Tool: {tool_name} -> {tool_args}")
                approval_status = "confirmed" if operator_approved else "unrestricted"

                tool_target = ""
                for _tk in ("target", "url", "rhosts", "host", "domain"):
                    if _tk in tool_args:
                        tool_target = str(tool_args[_tk])
                        break

                execution = ctx.tool_executor.execute(
                    tool_name,
                    tool_args,
                    target=tool_target,
                    approved=operator_approved,
                )
                result = execution.output
                raw_result = execution.raw_output
                logger.debug("Tool %s raw output (len=%d): %s", tool_name, len(raw_result), raw_result[:200])
                print(f"\n[RAW OUTPUT START] {tool_name}\n{raw_result}\n[RAW OUTPUT END]\n")
                print(f"[=] ผลลัพธ์กลับมาแล้ว (ความยาว: {len(raw_result)} ตัวอักษร)")

                _log_jsonl({
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    "type": "tool_call",
                    "tool_name": tool_name,
                    "tool_args": tool_args,
                    "raw_result": raw_result,
                    "approved": approval_status,
                    "evidence_cmd_sha256": execution.command_sha256,
                    "evidence_out_sha256": execution.output_sha256,
                }, ctx=ctx)

                tool_status = "failure" if execution.is_failure else "success"
                actually_invoked_tools.append({
                    "tool_name": tool_name,
                    "tool_args": tool_args,
                    "status": tool_status,
                    "raw_result": raw_result,
                })

                if execution.has_finding:
                    _record_finding(ctx, tool_name, tool_args, result, raw_result)

                fenced_result = fence_untrusted(result, source=tool_name)
                if tool_status == "failure":
                    observation = f"Observation: [TOOL EXECUTION FAILED] Raw error: {result}. Do NOT report findings from this call."
                elif execution.has_finding:
                    observation = f"Observation: {fenced_result} [FINDINGS DETECTED - use this data]"
                else:
                    observation = f"Observation: {fenced_result} [NO POSITIVE FINDINGS - do not invent any]"

                print(f"[OBSERVATION] {observation}")
                messages.append(AIMessage(content=observation))
                ctx.chat_history.append(AIMessage(content=observation))

                if tool_name not in CONFIRM_REQUIRED_TOOLS:
                    risk_score += RISK_POINTS["regular_tool"]
                    ctx.in_task_risk_events.append({"type": "regular_tool", "points": RISK_POINTS["regular_tool"]})
                    print(f"  [risk: {risk_score}/{threshold}]")
                continue

            else:
                raw_final = extract_final_answer(response_text)
                final = clean_answer_text(raw_final) if raw_final else None

                # Conversational Mode 1
                if not final:
                    if current_turn_target and not actually_invoked_tools and mode1_target_retry_count < 1:
                        mode1_target_retry_count += 1
                        correction = (
                            f"[SYSTEM NOTE] An active security assessment against target '{current_turn_target}' was requested. "
                            f"You MUST use ReAct format:\n"
                            f"Thought: (your tactical assessment plan)\n"
                            f"Action: (tool_name from available tools, e.g. whatweb_web_fingerprint, rustscan_port_scan, nmap_security_scan)\n"
                            f"Action Input: {{\"target\": \"{current_turn_target}\"}}\n\n"
                            f"Do NOT output direct claims or invent version details without executing tools."
                        )
                        messages.append(AIMessage(content=correction))
                        ctx.chat_history.append(AIMessage(content=correction))
                        continue

                    direct_text = response_text.strip()
                    if direct_text.startswith("Thought:"):
                        direct_text = re.sub(r"^Thought:\s*", "", direct_text).strip()
                    direct_text = clean_answer_text(direct_text)
                    if direct_text:
                        _log_jsonl({
                            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                            "type": "conversational_response",
                            "content": direct_text,
                            "step": step,
                            "safety_passed": True,
                            "task_number": current_task_number,
                        }, ctx=ctx)
                        session_manager.append_message(active_session, "assistant", direct_text)
                        return direct_text

                if final and is_placeholder_answer(final):
                    if placeholder_retry_count >= 1:
                        fallback = (
                            "[NOTE] LONLY failed to generate a real answer after repeated attempts. "
                            "Raw tool history above is the only reliable information for this task."
                        )
                        session_manager.append_message(active_session, "assistant", fallback)
                        return fallback
                    placeholder_retry_count += 1
                    _log_jsonl({
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                        "type": "placeholder_detected",
                        "content": final,
                        "step": step,
                    }, ctx=ctx)
                    ctx.carryover_event_log.append({
                        "task_number": current_task_number,
                        "event_type": "placeholder_answer",
                        "points": RISK_POINTS["placeholder_answer"],
                    })
                    correction = (
                        "[SYSTEM NOTE] You wrote a format example/placeholder instead of a real answer. "
                        "Write your own original summary based on the Observations you received. "
                        "If no positive findings were discovered, state that clearly per the FAILURES rule. "
                        "Do NOT copy instruction text or format examples."
                    )
                    messages.append(AIMessage(content=correction))
                    ctx.chat_history.append(AIMessage(content=correction))
                    continue

                fabricated = find_fabricated_tool_mentions(
                    final,
                    [d["tool_name"] for d in actually_invoked_tools],
                    list(tool_map.keys()),
                )
                overclaimed = check_overclaim(final, actually_invoked_tools)
                claim_check = ClaimVerifier(ctx.evidence_graph).verify_final_answer(final)
                is_safe = (not fabricated) and (not overclaimed) and (not claim_check.get("unsupported_claims"))

                _log_jsonl({
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    "type": "final_answer",
                    "content": final,
                    "step": step,
                    "safety_passed": is_safe,
                    "overclaim_detected": bool(overclaimed),
                    "fabrication_detected": bool(fabricated),
                    "unsupported_claims": claim_check.get("unsupported_claims", []),
                    "task_number": current_task_number,
                }, ctx=ctx)

                if overclaimed:
                    ctx.carryover_event_log.append({
                        "task_number": current_task_number,
                        "event_type": "overclaim",
                        "points": RISK_POINTS["overclaim"],
                    })
                    ctx.chat_history.append(AIMessage(
                        content=f"[SYSTEM NOTE] Your previous answer implied {overclaimed} produced "
                                f"findings, but raw output showed no positive result. Be careful not "
                                f"to repeat this kind of overclaiming."
                    ))
                if fabricated:
                    warning = (
                        f"⚠ [FABRICATION WARNING] The LLM's answer mentioned tool(s) "
                        f"{fabricated} which were never actually run. The raw tool history "
                        f"is shown above. Please verify specific claims against raw output.\n\n"
                    )
                    ctx.chat_history.append(AIMessage(
                        content=f"[SYSTEM NOTE] The LLM fabricated mention of {fabricated} in its answer. Future answers should not mention tools not invoked."
                    ))
                    _log_jsonl({
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                        "type": "fabrication_warning",
                        "fabricated_tools": fabricated,
                        "final_answer": final,
                    }, ctx=ctx)
                    ctx.carryover_event_log.append({
                        "task_number": current_task_number,
                        "event_type": "fabrication",
                        "points": RISK_POINTS["fabrication"],
                    })
                    full_ans = warning + final
                    session_manager.append_message(active_session, "assistant", full_ans)
                    return full_ans

                if overclaimed:
                    full_ans = (
                        f"⚠ [POSSIBLE OVERCLAIM] LONLY's answer below may overstate findings "
                        f"from: {overclaimed}. Raw output above showed no confirmed positive result "
                        f"for these tools. Compare carefully before trusting specific claims.\n\n"
                        f"{final}"
                    )
                    session_manager.append_message(active_session, "assistant", full_ans)
                    return full_ans

                if claim_check.get("unsupported_claims"):
                    _log_jsonl({
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                        "type": "unverified_claim",
                        "unsupported_claims": claim_check["unsupported_claims"],
                        "final_answer": final,
                    }, ctx=ctx)

                if ctx.findings_log.findings:
                    final = final + "\n\n[EVIDENCE LOG]\n" + ctx.findings_log.prompt_block()
                session_manager.append_message(active_session, "assistant", final)
                return final

        final_summary = "[-] สรุปผลการสแกนโดยสังเขป: " + summarize_findings(ctx.chat_history)
        _log_jsonl({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "type": "final_answer",
            "content": final_summary,
            "step": step,
            "safety_passed": True,
            "overclaim_detected": False,
            "fabrication_detected": False,
            "task_number": current_task_number,
        }, ctx=ctx)
        return final_summary
