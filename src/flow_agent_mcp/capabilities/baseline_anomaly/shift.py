from __future__ import annotations

import math
import time
from dataclasses import dataclass
from typing import Dict, List, Tuple


@dataclass
class ShiftEvent:
    dimension: str
    old_top: List[Tuple[str, float]]
    new_top: List[Tuple[str, float]]
    distance: float
    window_seconds: int
    ts: float


def _normalize(counts: Dict[str, float]) -> Dict[str, float]:
    total = sum(counts.values())
    if total <= 0:
        return {}
    return {k: v / total for k, v in counts.items()}


def l1_distance(p: Dict[str, float], q: Dict[str, float]) -> float:
    """
    L1 distance between two distributions.
    """
    keys = set(p.keys()) | set(q.keys())
    return sum(abs(p.get(k, 0.0) - q.get(k, 0.0)) for k in keys)


def top_k(dist: Dict[str, float], k: int = 5) -> List[Tuple[str, float]]:
    return sorted(dist.items(), key=lambda x: x[1], reverse=True)[:k]


class ShiftModel:
    """
    Maintains a previous window distribution per dimension.
    """

    def __init__(self) -> None:
        self._prev: Dict[str, Dict[str, float]] = {}
        self._prev_ts: Dict[str, float] = {}

    def update_and_detect(
        self,
        dimension: str,
        counts: Dict[str, float],
        threshold: float,
        min_total: float,
        window_seconds: int,
    ) -> ShiftEvent | None:
        """
        Detects traffic shifts using distribution distance.
        """
        total = sum(counts.values())
        if total < min_total:
            return None

        current = _normalize(counts)
        prev = self._prev.get(dimension)

        self._prev[dimension] = current
        self._prev_ts[dimension] = time.time()

        if prev is None:
            return None

        dist = l1_distance(prev, current)
        if dist >= threshold:
            return ShiftEvent(
                dimension=dimension,
                old_top=top_k(prev),
                new_top=top_k(current),
                distance=dist,
                window_seconds=window_seconds,
                ts=time.time(),
            )

        return None
