#!/usr/bin/env python3
"""eval/track_f_privesc.py — Track F: unit tests for _run_privesc_specialist().

This block (pentest_agent.py:204-251) is the N3 privesc delegation node:
  - config gate (LONLY_PRIVESC_SSH / LONLY_PRIVESC_USER -> None)
  - import fallback (privesc_protocol missing -> None)
  - SSH backend contracts (run_argv argv, timeout, max_output, got_root heuristics)
  - PrivescSpecialist construction (model, user, password, max_turns,
    trajectory_path) and run() result passthrough

No Ollama and no SSH ever runs: privesc_protocol is stubbed via sys.modules
and pentest_agent.run_argv is mocked.
"""
from __future__ import annotations

import builtins
import io
import os
import sys
import types
import unittest
from unittest.mock import patch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import pentest_agent as pa

ENV_KEYS = (
    "LONLY_PRIVESC_SSH",
    "LONLY_PRIVESC_USER",
    "LONLY_PRIVESC_PASSWORD",
    "LONLY_PRIVESC_MAX_TURNS",
)

FAKE_RUN_RESULT = {
    "success": True,
    "reason": "got_root",
    "turns": 4,
    "tool_calls": 12,
    "messages": [{"role": "assistant", "content": "<tool_call>{}" * 3}],
}


class FakeToolResult:
    """Mirror of models/privesc_protocol.ToolResult's minimal face."""

    def __init__(self, got_root: bool, output: str, timed_out: bool = False):
        self.got_root = got_root
        self.output = output
        self.timed_out = timed_out

    def to_json(self) -> str:
        return f'{{"got_root": {self.got_root}, "output": "{self.output}"}}'


class FakePrivescSpecialist:
    """Records constructor args; run() returns a canned dict."""

    last_instance = None
    instances: list = []

    def __init__(self, backend, model=None, user=None, password=None,
                 max_turns=None, trajectory_path=None):
        self.backend = backend
        self.model = model
        self.user = user
        self.password = password
        self.max_turns = max_turns
        self.trajectory_path = trajectory_path
        type(self).last_instance = self
        type(self).instances.append(self)

    def run(self):
        return dict(FAKE_RUN_RESULT)


def _fake_protocol() -> types.ModuleType:
    mod = types.ModuleType("privesc_protocol")
    mod.PrivescSpecialist = FakePrivescSpecialist
    mod.ToolResult = FakeToolResult
    return mod


class TestPrivescSpecialistBlock(unittest.TestCase):
    def setUp(self):
        for k in ENV_KEYS:
            os.environ.pop(k, None)
        sys.modules.pop("privesc_protocol", None)
        FakePrivescSpecialist.last_instance = None
        FakePrivescSpecialist.instances = []
        pa._default_context().findings_log = pa.FindingsLog(run_dir="/tmp/lonly_track_f_run")

    # -- helper: full happy-path invocation -------------------------------
    def _run_with_backend(self, run_argv_ret="uid=1000(user) gid=1000"):
        with patch.dict(sys.modules, {"privesc_protocol": _fake_protocol()}):
            with patch("pentest_agent.run_argv", return_value=run_argv_ret) as m:
                result = pa._run_privesc_specialist()
        return result, m, FakePrivescSpecialist.last_instance

    # -- F1/F2 config gate ------------------------------------------------
    def test_f1_config_gate_no_ssh(self):
        os.environ["LONLY_PRIVESC_USER"] = "alice"
        self.assertIsNone(pa._run_privesc_specialist())

    def test_f2_config_gate_no_user(self):
        os.environ["LONLY_PRIVESC_SSH"] = "10.0.0.5"
        self.assertIsNone(pa._run_privesc_specialist())

    # -- F3 import fallback ------------------------------------------------
    def test_f3_import_failure_returns_none(self):
        os.environ["LONLY_PRIVESC_SSH"] = "10.0.0.5"
        os.environ["LONLY_PRIVESC_USER"] = "alice"
        sys.modules.pop("privesc_protocol", None)
        real_import = builtins.__import__
        def _raise(name, *args, **kwargs):
            if name == "privesc_protocol":
                raise ImportError("simulated missing module")
            return real_import(name, *args, **kwargs)
        with patch("builtins.__import__", side_effect=_raise):
            self.assertIsNone(pa._run_privesc_specialist())

    # -- F4 happy path: construction + passthrough + delegation print ------
    def test_f4_constructs_spec_and_passthroughs_result(self):
        os.environ["LONLY_PRIVESC_SSH"] = "10.0.0.5"
        os.environ["LONLY_PRIVESC_USER"] = "alice"
        os.environ["LONLY_PRIVESC_PASSWORD"] = "s3cret"
        spec = FakePrivescSpecialist.last_instance
        with patch("builtins.print") as p:
            result, _, spec = self._run_with_backend()
        self.assertEqual(result, FAKE_RUN_RESULT)
        self.assertIsNotNone(spec)
        self.assertEqual(spec.user, "alice")
        self.assertEqual(spec.password, "s3cret")
        self.assertEqual(spec.model, pa.PHASE_MODEL_MAP.get("privesc"))
        prints = [str(c.args[0]) for c in p.call_args_list]
        self.assertTrue(
            any("delegating to specialist" in s and "10.0.0.5" in s for s in prints),
            f"delegation print missing: {prints}",
        )

    # -- F5 defaults: password "" / max_turns 20 ---------------------------
    def test_f5_defaults_password_and_max_turns(self):
        os.environ["LONLY_PRIVESC_SSH"] = "10.0.0.5"
        os.environ["LONLY_PRIVESC_USER"] = "alice"
        _, _, spec = self._run_with_backend()
        self.assertEqual(spec.password, "")
        self.assertEqual(spec.max_turns, 20)

    # -- F6 max_turns env override + garbage handling ----------------------
    def test_f6_max_turns_env_override(self):
        os.environ["LONLY_PRIVESC_SSH"] = "10.0.0.5"
        os.environ["LONLY_PRIVESC_USER"] = "alice"
        os.environ["LONLY_PRIVESC_MAX_TURNS"] = "7"
        _, _, spec = self._run_with_backend()
        self.assertEqual(spec.max_turns, 7)

    def test_f6b_max_turns_garbage_raises_value_error(self):
        os.environ["LONLY_PRIVESC_SSH"] = "10.0.0.5"
        os.environ["LONLY_PRIVESC_USER"] = "alice"
        os.environ["LONLY_PRIVESC_MAX_TURNS"] = "abc"
        with self.assertRaises(ValueError):
            self._run_with_backend()

    # -- F7 SSH argv contract ----------------------------------------------
    def test_f7_ssh_argv_contract(self):
        os.environ["LONLY_PRIVESC_SSH"] = "10.0.0.5"
        os.environ["LONLY_PRIVESC_USER"] = "alice"
        with patch.dict(sys.modules, {"privesc_protocol": _fake_protocol()}):
            with patch("pentest_agent.run_argv", return_value="uid=1000(user) gid=1000") as m:
                pa._run_privesc_specialist()
                backend = FakePrivescSpecialist.last_instance.backend
                out = backend.exec_command("whoami")
        m.assert_called_once_with(
            "ssh",
            [
                "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=accept-new",
                "-o", "ConnectTimeout=10",
                "10.0.0.5",
                "whoami",
            ],
            target="10.0.0.5",
            capability="privesc_specialist_ssh",
            timeout=60,
            max_output=2000,
        )
        self.assertFalse(out.got_root)
        self.assertEqual(out.output, "uid=1000(user) gid=1000")

    # -- F8 _got_root heuristics -------------------------------------------
    def test_f8_got_root_heuristics(self):
        os.environ["LONLY_PRIVESC_SSH"] = "10.0.0.5"
        os.environ["LONLY_PRIVESC_USER"] = "alice"
        cases = [
            ("uid=0(root) gid=0(root)", True),
            ("euid=0 uid=1000", True),
            ("root@host:~#", True),
            ("uid=1000(user) gid=1000(users)", False),
            ("Permission denied (publickey).", False),
            ("", False),
        ]
        outputs = [out for out, _ in cases]
        with patch.dict(sys.modules, {"privesc_protocol": _fake_protocol()}):
            with patch("pentest_agent.run_argv", side_effect=outputs):
                pa._run_privesc_specialist()
                backend = FakePrivescSpecialist.last_instance.backend
                for out, expected in cases:
                    res = backend.exec_command("id")
                    self.assertEqual(res.got_root, expected, f"output={out!r}")

    # -- F9 test_credentials is a no-op ------------------------------------
    def test_f9_test_credentials_returns_failure(self):
        os.environ["LONLY_PRIVESC_SSH"] = "10.0.0.5"
        os.environ["LONLY_PRIVESC_USER"] = "alice"
        _, _, spec = self._run_with_backend()
        res = spec.backend.test_credentials("alice", "pw")
        self.assertFalse(res.got_root)
        self.assertIn("not wired", res.output)

    # -- F10 trajectory path + PHASE_MODEL_MAP fallback ---------------------
    def test_f10_trajectory_path_under_run_dir(self):
        os.environ["LONLY_PRIVESC_SSH"] = "10.0.0.5"
        os.environ["LONLY_PRIVESC_USER"] = "alice"
        _, _, spec = self._run_with_backend()
        self.assertEqual(
            spec.trajectory_path,
            os.path.join(pa._default_context().findings_log.run_dir, "privesc_trajectories.jsonl"),
        )

    def test_f10b_phase_model_map_fallback(self):
        os.environ["LONLY_PRIVESC_SSH"] = "10.0.0.5"
        os.environ["LONLY_PRIVESC_USER"] = "alice"
        with patch.object(pa, "PHASE_MODEL_MAP", {}):
            _, _, spec = self._run_with_backend()
        self.assertEqual(spec.model, "privesc-llm-rl:4b")

    def test_f10c_phase_model_custom_passthrough(self):
        os.environ["LONLY_PRIVESC_SSH"] = "10.0.0.5"
        os.environ["LONLY_PRIVESC_USER"] = "alice"
        with patch.object(pa, "PHASE_MODEL_MAP", {"privesc": "custom-llm:4b"}):
            _, _, spec = self._run_with_backend()
        self.assertEqual(spec.model, "custom-llm:4b")


FIXTURE_NAMES = [
    ("F1 config gate: missing SSH/user -> None", ""),
    ("F2 config gate: missing user -> None", ""),
    ("F3 import fallback: missing privesc_protocol -> None", ""),
    ("F4 happy path: spec construction + result passthrough + delegation print", ""),
    ("F5 defaults: password '' and max_turns 20", ""),
    ("F6 max_turns env override (+ garbage -> ValueError contract)", ""),
    ("F7 SSH backend: run_argv argv/timeout/max_output contract", ""),
    ("F8 got_root heuristics (uid=0/euid=0/root@ vs user/denied/empty)", ""),
    ("F9 test_credentials stub returns got_root=False", ""),
    ("F10 trajectory path + PHASE_MODEL_MAP fallback/custom", ""),
]


def run_track_f_fixtures() -> list[tuple[str, bool, str]]:
    suite = unittest.TestLoader().loadTestsFromTestCase(TestPrivescSpecialistBlock)
    runner = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0)
    result = runner.run(suite)

    fixtures = [(name, True, "") for name, _ in FIXTURE_NAMES]
    if not result.wasSuccessful():
        for i, failure in enumerate(result.failures + result.errors):
            idx = min(i, len(fixtures) - 1)
            fixtures[idx] = (fixtures[idx][0], False, str(failure[1]))
    return fixtures


if __name__ == "__main__":
    unittest.main()
