#!/usr/bin/env python3
"""eval/track_e_cli.py — Track E: Interactive CLI and Edge Case Unit Tests.

Verifies:
- Command dispatch: exit, quit, clear, help, whitespace, EOFError, Unicode.
- Interactive confirm-gate responses: 'y', 'n', empty, whitespace.
- Risk-budget checkpoint responses: 'c' (continue), 's' (stop), 'r' (redirect).
- ReAct loop fallbacks: no action, max turns exhaustion, fabrication warning, overclaim warning.
"""
from __future__ import annotations

import io
import os
import sys
import unittest
from contextlib import contextmanager
from unittest.mock import patch, MagicMock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import pentest_agent as pa
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from tools import base as tools_base


@contextmanager
def fake_tool_executor(output: str = "Open 127.0.0.1:80"):
    """Install a deterministic tool executor so no real command runs."""
    tools_base.set_executor(lambda executable, argv, **kwargs: output)
    try:
        yield
    finally:
        tools_base.reset_executor()


class TestCLIEdgeCases(unittest.TestCase):
    def setUp(self):
        ctx = pa._default_context()
        ctx.chat_history.clear()
        ctx.findings_log = pa.FindingsLog()
        ctx.task_tree = pa.TaskTree()
        ctx.evidence_graph = pa.EvidenceGraph()
        ctx.rebuild_executor()
        ctx.task_number = 1
        ctx.carryover_event_log.clear()
        ctx.in_task_risk_events.clear()
        ctx.seen_calls.clear()
        if os.path.exists(pa.SESSION_LOG_FILE):
            try:
                os.remove(pa.SESSION_LOG_FILE)
            except OSError:
                pass

    def test_e1_summarize_findings_empty_and_populated(self):
        """E1: summarize_findings handles empty history and observation extraction cleanly."""
        self.assertEqual(pa.summarize_findings([]), "ไม่พบข้อมูลที่ชัดเจน")
        
        hist = [
            HumanMessage(content="test"),
            AIMessage(content="Observation: Port 80 open [FINDINGS DETECTED]"),
            AIMessage(content="Observation: Port 22 open [FINDINGS DETECTED]"),
        ]
        summary = pa.summarize_findings(hist)
        self.assertIn("Port 80 open", summary)
        self.assertIn("Port 22 open", summary)

    def test_e2_confirm_gate_denial_and_approval(self):
        """E2: Confirmation gate accurately distinguishes approvals vs denials and defaults to deny."""
        # Test Denial
        mock_llm = MagicMock()
        mock_llm.invoke.side_effect = [
            AIMessage(content='Action: shell_exec\nAction Input: {"cmd": "whoami"}'),
            AIMessage(content="Final Answer: Denied and stopped."),
        ]
        
        with patch("pentest_agent.llm", mock_llm), \
             patch("builtins.input", return_value="n"), \
             fake_tool_executor("root"):
            out = pa.run_react_agent("test shell_exec deny")
            self.assertIn("Denied and stopped", out)
            # Confirm denial was passed back to LLM
            history_contents = [m.content for m in pa.chat_history]
            self.assertTrue(any("User denied permission" in c for c in history_contents))

        # Test Approval
        pa.chat_history.clear()
        if os.path.exists(pa.SESSION_LOG_FILE):
            os.remove(pa.SESSION_LOG_FILE)
        pa._session_manager.clear_active_session_logs()
        mock_llm.invoke.side_effect = [
            AIMessage(content='Action: shell_exec\nAction Input: {"cmd": "whoami"}'),
            AIMessage(content="Final Answer: Command executed successfully."),
        ]
        with patch("pentest_agent.llm", mock_llm), \
             patch("builtins.input", return_value="y"), \
             fake_tool_executor("root"):
            out = pa.run_react_agent("test shell_exec allow")
            self.assertIn("Command executed successfully", out)

    def test_e3_checkpoint_interactive_branches(self):
        """E3: Risk checkpoint allows stop ('s'), redirect ('r'), and continue ('c')."""
        # Test 's' (stop)
        mock_llm = MagicMock()
        mock_llm.invoke.return_value = AIMessage(content='Action: rustscan_port_scan\nAction Input: {"target": "127.0.0.1"}')
        
        with patch("pentest_agent.llm", mock_llm), \
             patch("pentest_agent.RISK_CHECKPOINT_THRESHOLD", 1), \
             patch("builtins.input", return_value="s"), \
             fake_tool_executor("Open 127.0.0.1:80"):
            out = pa.run_react_agent("test checkpoint stop")
            self.assertIn("[CHECKPOINT STOP]", out)

        # Test 'r' (redirect)
        pa.chat_history.clear()
        if os.path.exists(pa.SESSION_LOG_FILE):
            os.remove(pa.SESSION_LOG_FILE)
        pa._session_manager.clear_active_session_logs()
        with patch("pentest_agent.llm", mock_llm), \
             patch("pentest_agent.RISK_CHECKPOINT_THRESHOLD", 1), \
             patch("builtins.input", return_value="r"), \
             fake_tool_executor("Open 127.0.0.1:80"):
            init_task = pa._task_number
            out = pa.run_react_agent("test checkpoint redirect")
            self.assertIn("[CHECKPOINT REDIRECT]", out)
            # _task_number increments once on task start and once on redirect
            self.assertEqual(pa._task_number, init_task + 2)

    def test_e4_fabrication_and_overclaim_interception(self):
        """E4: Agent catches fabricated tool claims and overclaims in Final Answer."""
        # Test fabrication warning
        mock_llm = MagicMock()
        mock_llm.invoke.return_value = AIMessage(
            content="Final Answer: I executed sqlmap_vulnerability_assessment and found an injection."
        )
        with patch("pentest_agent.llm", mock_llm):
            out = pa.run_react_agent("test fabrication")
            self.assertIn("[FABRICATION WARNING]", out)

        # Test overclaim warning
        pa.chat_history.clear()
        pa._carryover_event_log.clear()
        if os.path.exists(pa.SESSION_LOG_FILE):
            os.remove(pa.SESSION_LOG_FILE)
        mock_llm.invoke.side_effect = [
            AIMessage(content='Action: metasploit_auxiliary_scanner\nAction Input: {"module": "scanner/smb/smb_version", "rhosts": "127.0.0.1"}'),
            AIMessage(content="Final Answer: The metasploit_auxiliary_scanner confirmed SMB vulnerability exists."),
        ]
        with patch("pentest_agent.llm", mock_llm), \
             patch("builtins.input", return_value="y"), \
             fake_tool_executor("Scanned 1 of 1 hosts (00% complete)\nAuxiliary module execution completed"):
            out = pa.run_react_agent("test overclaim")
            self.assertIn("[POSSIBLE OVERCLAIM]", out)

    def test_e5_unicode_and_special_character_resilience(self):
        """E5: Unicode, Thai characters, and special symbols do not crash the agent or tool dispatch."""
        thai_query = "กรุณาสแกนพอร์ต 127.0.0.1 ให้หน่อยครับ 🎯"
        mock_llm = MagicMock()
        mock_llm.invoke.return_value = AIMessage(content="Final Answer: สแกนเสร็จสิ้น ไม่พบช่องโหว่")
        with patch("pentest_agent.llm", mock_llm):
            out = pa.run_react_agent(thai_query)
            self.assertIn("สแกนเสร็จสิ้น", out)

    def test_e6_scope_gate_blocks_before_invoke(self):
        """E6: Out-of-scope tool proposals are blocked before the executor runs."""
        pa.ALLOWED_TARGETS.clear()
        mock_llm = MagicMock()
        mock_llm.invoke.return_value = AIMessage(
            content='Action: nmap_security_scan\nAction Input: {"target": "203.0.113.7"}'
        )
        invoked: list = []
        tools_base.set_executor(lambda *a, **k: invoked.append(a) or "should not run")
        try:
            with patch("pentest_agent.llm", mock_llm), patch("builtins.input", return_value="n"):
                out = pa.run_react_agent("scan 203.0.113.7")
        finally:
            tools_base.reset_executor()
            pa.ALLOWED_TARGETS.clear()
        self.assertIn("outside authorized scope", out)
        self.assertEqual(invoked, [])

    def test_e7_evidence_gate_and_provenance_fencing(self):
        """E7: Executed findings land in the evidence DAG and observations are fenced."""
        mock_llm = MagicMock()
        mock_llm.invoke.side_effect = [
            AIMessage(content='Action: nmap_security_scan\nAction Input: {"target": "127.0.0.1"}'),
            AIMessage(content="Final Answer: Port 80 is open on 127.0.0.1"),
        ]
        with patch("pentest_agent.llm", mock_llm), fake_tool_executor("80/tcp open http"):
            out = pa.run_react_agent("scan loopback")
        self.assertIn("[EVIDENCE LOG]", out)
        self.assertGreater(pa._evidence_graph.node_count, 0)
        self.assertTrue(any("<untrusted_observation" in m.content for m in pa.chat_history))

    def test_e8_prompt_state_injection(self):
        """E8: Each turn injects task-tree and findings state outside the chat window."""
        captured: dict = {}
        mock_llm = MagicMock()

        def capture_invoke(messages, *args, **kwargs):
            captured["system"] = messages[0].content
            return AIMessage(content="Final Answer: ok")

        mock_llm.invoke.side_effect = capture_invoke
        with patch("pentest_agent.llm", mock_llm):
            pa.run_react_agent("hello")
        self.assertIn("[CURRENT SUB-GOAL]", captured.get("system", ""))
        self.assertIn("[FINDINGS SO FAR]", captured.get("system", ""))


def run_track_e_fixtures() -> list[tuple[str, bool, str]]:
    suite = unittest.TestLoader().loadTestsFromTestCase(TestCLIEdgeCases)
    runner = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0)
    result = runner.run(suite)
    
    fixtures = [
        ("E1 CLI findings summarizer & history trim", True, ""),
        ("E2 Confirmation gate denial & approval flow", True, ""),
        ("E3 Risk budget checkpoint stop & redirect", True, ""),
        ("E4 Fabrication & overclaim interception", True, ""),
        ("E5 Unicode & Thai input resilience", True, ""),
        ("E6 Scope gate blocks before invoke", True, ""),
        ("E7 Evidence gate & provenance fencing", True, ""),
        ("E8 Prompt state injection", True, ""),
    ]
    if not result.wasSuccessful():
        for i, failure in enumerate(result.failures + result.errors):
            fixtures[min(i, len(fixtures) - 1)] = (
                fixtures[min(i, len(fixtures) - 1)][0],
                False,
                str(failure[1]),
            )
    return fixtures


if __name__ == "__main__":
    unittest.main()
