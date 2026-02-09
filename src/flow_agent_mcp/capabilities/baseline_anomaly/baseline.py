from __future__ import annotations

import math
import time
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple


@dataclass
class BaselinePoint:
    """
    Stores a rolling baseline for a metric.

    We use EWMA and EWM variance because it is:
      - fast
      - robust enough for streaming
      - simple to explain and tune

    The baseline is updated only when we have enough samples for the window.
    """

    mean: float = 0.0
    var: float = 0.0
    n: int = 0
    last_update_ts: float = 0.0

    def update(self, x: float, alpha: float) -> None:
        """
        EWMA update for mean and variance.
        """
        if self.n == 0:
            self.mean = x
            self.var = 0.0
            self.n = 1
            self.last_update_ts = time.time()
            return

        # EWMA mean update
        prev_mean = self.mean
        self.mean = (alpha * x) + ((1.0 - alpha) * self.mean)

        # EWM variance update using squared residual
        residual = x - prev_mean
        self.var = (alpha * (residual * residual)) + ((1.0 - alpha) * self.var)

        self.n += 1
        self.last_update_ts = time.time()

    def std(self) -> float:
        return math.sqrt(max(self.var, 0.0))


def percentile(values: List[float], p: float) -> float:
    """
    Simple percentile helper.
    p in [0, 100]
    """
    if not values:
        return 0.0
    if p <= 0:
        return min(values)
    if p >= 100:
        return max(values)

    values_sorted = sorted(values)
    k = (len(values_sorted) - 1) * (p / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return values_sorted[int(k)]
    d0 = values_sorted[f] * (c - k)
    d1 = values_sorted[c] * (k - f)
    return d0 + d1


def compute_window_stats(latencies_ms: List[float]) -> Dict[str, float]:
    """
    Returns stats needed for baseline and alert decisions.
    """
    if not latencies_ms:
        return {"p50": 0.0, "p95": 0.0, "count": 0}

    return {
        "p50": percentile(latencies_ms, 50),
        "p95": percentile(latencies_ms, 95),
        "count": float(len(latencies_ms)),
    }


@dataclass
class AnomalyEvent:
    key: str
    metric: str
    current: float
    baseline_mean: float
    baseline_std: float
    zscore: float
    window_seconds: int
    sample_count: int
    ts: float


class BaselineModel:
    """
    Maintains baselines per key and metric.

    Example keys:
      exporter:1.2.3.4
      src_asn:7922
      dst_asn:15169
      pair_asn:7922->15169
      site:sjc

    Metrics:
      p50_ms
      p95_ms
    """

    def __init__(self) -> None:
        self._points: Dict[Tuple[str, str], BaselinePoint] = {}

    def get_point(self, key: str, metric: str) -> BaselinePoint:
        k = (key, metric)
        if k not in self._points:
            self._points[k] = BaselinePoint()
        return self._points[k]

    def update(self, key: str, metric: str, value: float, alpha: float) -> BaselinePoint:
        pt = self.get_point(key, metric)
        pt.update(value, alpha=alpha)
        return pt

    def detect_anomaly(
        self,
        key: str,
        metric: str,
        current_value: float,
        z_threshold: float,
        min_updates: int,
    ) -> Optional[Tuple[float, float, float]]:
        """
        Returns (mean, std, zscore) if anomaly, else None.
        Important behavior:
          - If the baseline variance is zero and the value changes,
            treat it as an anomaly.
          - This prevents perfectly stable baselines from masking spikes.
        """
        pt = self.get_point(key, metric)
        
        #Not enough historical data yet
        if pt.n < min_updates:
            return None

        std = pt.std()
        # ------------------------------------------------------------
        # Zero variance guard
        #
        # If the baseline has learned a perfectly flat signal (std ~ 0),
        # any deviation from the mean is significant.
        #
        # This commonly happens in tests and in real networks during
        # steady state operation.
        # ------------------------------------------------------------ 
        if std <= 1e-9:
            if current_value != pt.mean:
                return (pt.mean, std, float("inf"))
            return None

        # Standard z-score detection
        z = (current_value - pt.mean) / std
        if abs(z) >= z_threshold:
            return (pt.mean, std, z)

        return None
