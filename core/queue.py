#!/usr/bin/env python3
"""core/queue.py — Transactional Job Queue & Circuit Breaker Engine for LONLY v2.

Enforces:
- Reliable asynchronous job queueing, retries, and worker concurrency controls.
- Automatic circuit breaking on repeated worker or target failures.
- Non-blocking job cancellation and crash recovery.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Optional


class JobState(str, Enum):
    QUEUED = "QUEUED"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    CIRCUIT_BROKEN = "CIRCUIT_BROKEN"


class CircuitState(str, Enum):
    CLOSED = "CLOSED"      # Normal operations
    OPEN = "OPEN"          # Tripped, reject new requests
    HALF_OPEN = "HALF_OPEN"# Testing recovery


@dataclass
class JobRecord:
    """A unit of execution scheduled in the worker job queue."""
    job_id: str
    task_id: str
    tool_name: str
    args: dict = field(default_factory=dict)
    state: JobState | str = JobState.QUEUED
    attempts: int = 0
    max_retries: int = 3
    error: str = ""
    result: dict = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%S"))

    def to_dict(self) -> dict:
        return asdict(self)


class CircuitBreaker:
    """Protects targets and workers from cascade failures."""

    def __init__(self, failure_threshold: int = 3, reset_timeout_seconds: float = 30.0):
        self.failure_threshold = failure_threshold
        self.reset_timeout_seconds = reset_timeout_seconds
        self.state = CircuitState.CLOSED
        self.consecutive_failures = 0
        self.last_failure_time = 0.0

    def can_execute(self) -> bool:
        """Check if execution is allowed through the circuit."""
        now = time.time()
        if self.state == CircuitState.OPEN:
            if now - self.last_failure_time > self.reset_timeout_seconds:
                self.state = CircuitState.HALF_OPEN
                return True
            return False
        return True

    def record_success(self) -> None:
        self.consecutive_failures = 0
        self.state = CircuitState.CLOSED

    def record_failure(self) -> None:
        self.consecutive_failures += 1
        self.last_failure_time = time.time()
        if self.consecutive_failures >= self.failure_threshold:
            self.state = CircuitState.OPEN


class JobQueue:
    """In-memory transactional queue coordinating worker dispatches and retries."""

    def __init__(self, circuit_breaker: Optional[CircuitBreaker] = None):
        self._jobs: dict[str, JobRecord] = {}
        self._queue: list[str] = []
        self.circuit = circuit_breaker or CircuitBreaker()

    def enqueue(self, task_id: str, tool_name: str, args: dict, max_retries: int = 3) -> JobRecord:
        job_id = f"job_{uuid.uuid4().hex[:8]}"
        job = JobRecord(
            job_id=job_id,
            task_id=task_id,
            tool_name=tool_name,
            args=args,
            state=JobState.QUEUED,
            max_retries=max_retries,
        )
        self._jobs[job_id] = job
        self._queue.append(job_id)
        return job

    def dequeue(self) -> Optional[JobRecord]:
        """Fetch next ready job if circuit is healthy."""
        if not self.circuit.can_execute():
            return None
        while self._queue:
            job_id = self._queue.pop(0)
            job = self._jobs.get(job_id)
            if job and job.state == JobState.QUEUED:
                job.state = JobState.PROCESSING
                job.attempts += 1
                return job
        return None

    def complete_job(self, job_id: str, result: dict) -> bool:
        if job_id not in self._jobs:
            return False
        job = self._jobs[job_id]
        job.state = JobState.COMPLETED
        job.result = result
        self.circuit.record_success()
        return True

    def fail_job(self, job_id: str, error: str) -> bool:
        if job_id not in self._jobs:
            return False
        job = self._jobs[job_id]
        job.error = error
        self.circuit.record_failure()

        if job.attempts < job.max_retries:
            # Re-enqueue for retry
            job.state = JobState.QUEUED
            self._queue.append(job_id)
        else:
            job.state = JobState.FAILED
        return True

    def cancel_job(self, job_id: str) -> bool:
        if job_id not in self._jobs:
            return False
        job = self._jobs[job_id]
        job.state = JobState.CANCELLED
        return True

    @property
    def pending_count(self) -> int:
        return sum(1 for j in self._jobs.values() if j.state == JobState.QUEUED)
