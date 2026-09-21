#!/usr/bin/env python3
"""core/model_client.py — Resilient LLM client wrapper with timeout, retry, and circuit breaker.

Protects LONLY orchestration against hung model calls, transient network glitches,
and prolonged model downtime. Conforms to the LLMPort protocol.
"""
from __future__ import annotations

import concurrent.futures
import os
import time
from typing import Any, Callable, Optional, Sequence


class CircuitOpenError(RuntimeError):
    """Raised when an LLM invocation is refused because the circuit breaker is OPEN."""
    pass


class CircuitBreakerState:
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class ResilientLLM:
    """Resilient LLMPort wrapper providing bounded latency, retries, and circuit breaking."""

    def __init__(
        self,
        inner: Any,
        *,
        timeout: float = 120.0,
        retries: int = 2,
        backoff: float = 1.0,
        backoff_max: float = 30.0,
        circuit_threshold: int = 5,
        circuit_cooldown: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.inner = inner
        self.timeout = float(timeout)
        self.retries = int(retries)
        self.backoff = float(backoff)
        self.backoff_max = float(backoff_max)
        self.circuit_threshold = int(circuit_threshold)
        self.circuit_cooldown = float(circuit_cooldown)
        self.clock = clock
        self.sleep = sleep

        self._state = CircuitBreakerState.CLOSED
        self._consecutive_failures = 0
        self._opened_at = 0.0
        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=8, thread_name_prefix="resilient_llm"
        )

    @classmethod
    def from_env(cls, inner: Any) -> ResilientLLM:
        """Construct a ResilientLLM configured via standard environment variables."""
        return cls(
            inner=inner,
            timeout=float(os.environ.get("LONLY_LLM_TIMEOUT", "120.0")),
            retries=int(os.environ.get("LONLY_LLM_RETRIES", "2")),
            backoff=float(os.environ.get("LONLY_LLM_BACKOFF", "1.0")),
            backoff_max=float(os.environ.get("LONLY_LLM_BACKOFF_MAX", "30.0")),
            circuit_threshold=int(os.environ.get("LONLY_LLM_CIRCUIT_THRESHOLD", "5")),
            circuit_cooldown=float(os.environ.get("LONLY_LLM_CIRCUIT_COOLDOWN", "30.0")),
        )

    def _check_circuit(self) -> None:
        """Evaluate circuit breaker state before attempting an invocation."""
        if self._state == CircuitBreakerState.OPEN:
            now = self.clock()
            elapsed = now - self._opened_at
            if elapsed >= self.circuit_cooldown:
                self._state = CircuitBreakerState.HALF_OPEN
            else:
                remaining = self.circuit_cooldown - elapsed
                raise CircuitOpenError(
                    f"Circuit breaker is OPEN. Cooldown active ({remaining:.1f}s remaining)."
                )

    def _on_success(self) -> None:
        """Record successful invocation outcome."""
        self._consecutive_failures = 0
        self._state = CircuitBreakerState.CLOSED

    def _on_failure(self) -> None:
        """Record invocation failure and adjust breaker state."""
        self._consecutive_failures += 1
        if self._state == CircuitBreakerState.HALF_OPEN or self._consecutive_failures >= self.circuit_threshold:
            self._state = CircuitBreakerState.OPEN
            self._opened_at = self.clock()

    def _invoke_with_timeout(self, messages: Sequence[Any]) -> Any:
        """Invoke inner LLM with strict wall-clock timeout."""
        future = self._executor.submit(self.inner.invoke, messages)
        try:
            return future.result(timeout=self.timeout)
        except concurrent.futures.TimeoutError as err:
            future.cancel()
            raise TimeoutError(f"LLM invoke exceeded timeout of {self.timeout}s") from err

    def invoke(self, messages: Sequence[Any]) -> Any:
        """Invoke language model with timeout, retries, and circuit breaker protection."""
        self._check_circuit()
        last_exc: Optional[Exception] = None

        for attempt in range(self.retries + 1):
            # Check circuit state if retrying
            if attempt > 0:
                self._check_circuit()

            try:
                result = self._invoke_with_timeout(messages)
                self._on_success()
                return result
            except Exception as exc:
                last_exc = exc
                self._on_failure()
                if self._state == CircuitBreakerState.OPEN and attempt < self.retries:
                    raise CircuitOpenError(
                        "Circuit breaker tripped to OPEN during retry attempts."
                    ) from exc

                if attempt < self.retries:
                    delay = min(self.backoff * (2 ** attempt), self.backoff_max)
                    self.sleep(delay)

        assert last_exc is not None
        raise last_exc
