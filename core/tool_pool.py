#!/usr/bin/env python3
"""core/tool_pool.py — Bounded concurrent worker execution pool.

Provides thread-pool concurrency primitives preserving deterministic ordering.
"""
from __future__ import annotations

import concurrent.futures
from typing import Callable, Iterable, List, Optional, Tuple, TypeVar

T = TypeVar("T")
R = TypeVar("R")


def parallel_map(
    fn: Callable[[T], R],
    items: Iterable[T],
    max_workers: int = 4,
    timeout: Optional[float] = None,
) -> Tuple[List[Optional[R]], List[Optional[Exception]]]:
    """Execute `fn` across `items` in parallel with bounded worker threads.

    Returns (results, errors) tuples, maintaining strictly the input order.
    """
    item_list = list(items)
    n = len(item_list)
    results: List[Optional[R]] = [None] * n
    errors: List[Optional[Exception]] = [None] * n

    if n == 0:
        return results, errors

    workers = min(max_workers, n) if max_workers > 0 else 1
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_idx = {executor.submit(fn, item): i for i, item in enumerate(item_list)}
        for future in concurrent.futures.as_completed(future_to_idx, timeout=timeout):
            idx = future_to_idx[future]
            try:
                results[idx] = future.result()
            except Exception as exc:
                errors[idx] = exc

    return results, errors
