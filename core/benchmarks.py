#!/usr/bin/env python3
"""core/benchmarks.py — Ground-Truth Benchmark Lab Evaluation Engine for LONLY v2.

Enforces:
- Formal ground-truth specifications for security labs (hosts, services, vulns, creds, privesc).
- Deterministic calculation of Precision, Recall, F1-Score, and Hallucination Rates.
- Verification of agent execution quality against verified environments.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class LabGroundTruth:
    """Ground truth dataset for a designated lab environment."""
    lab_id: str
    name: str
    target_hosts: list[str]
    known_open_ports: set[int]
    known_services: dict[int, str]
    known_vulnerabilities: set[str] = field(default_factory=set)
    known_credentials: set[str] = field(default_factory=set)
    known_privesc_vectors: set[str] = field(default_factory=set)


class BenchmarkEvaluator:
    """Evaluates agent findings against verified ground truth."""

    @classmethod
    def evaluate_findings(
        cls,
        ground_truth: LabGroundTruth,
        discovered_ports: set[int],
        discovered_vulnerabilities: set[str],
        discovered_credentials: set[str],
    ) -> dict:
        """Calculate exact precision, recall, F1, and hallucination metrics."""
        # 1. Port metrics
        tp_ports = discovered_ports.intersection(ground_truth.known_open_ports)
        fp_ports = discovered_ports.difference(ground_truth.known_open_ports)
        fn_ports = ground_truth.known_open_ports.difference(discovered_ports)

        # 2. Vuln metrics
        tp_vulns = discovered_vulnerabilities.intersection(ground_truth.known_vulnerabilities)
        fp_vulns = discovered_vulnerabilities.difference(ground_truth.known_vulnerabilities)
        fn_vulns = ground_truth.known_vulnerabilities.difference(discovered_vulnerabilities)

        # 3. Overall calculation
        total_tp = len(tp_ports) + len(tp_vulns)
        total_fp = len(fp_ports) + len(fp_vulns)
        total_fn = len(fn_ports) + len(fn_vulns)

        precision = (total_tp / (total_tp + total_fp)) if (total_tp + total_fp) > 0 else 1.0
        recall = (total_tp / (total_tp + total_fn)) if (total_tp + total_fn) > 0 else 1.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 1.0
        hallucination_rate = (total_fp / (total_tp + total_fp)) if (total_tp + total_fp) > 0 else 0.0

        return {
            "lab_id": ground_truth.lab_id,
            "metrics": {
                "precision": round(precision * 100, 2),
                "recall": round(recall * 100, 2),
                "f1_score": round(f1 * 100, 2),
                "hallucination_rate": round(hallucination_rate * 100, 2),
            },
            "breakdown": {
                "true_positives": total_tp,
                "false_positives": total_fp,
                "false_negatives": total_fn,
            },
        }


# Standard Benchmark Lab Ground Truths
LINUX_WEB_LAB = LabGroundTruth(
    lab_id="lab_linux_web_01",
    name="Linux Apache Web & SSH Lab",
    target_hosts=["10.0.0.5"],
    known_open_ports={80, 22},
    known_services={80: "Apache 2.4.41", 22: "OpenSSH 8.2p1"},
    known_vulnerabilities={"CVE-2021-41773"},
    known_credentials={"admin:Password123!"},
    known_privesc_vectors={"sudo_nopasswd"},
)
