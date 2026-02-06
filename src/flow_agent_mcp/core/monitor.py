from __future__ import annotations
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional
from .models import FlowRecord
from .dedupe import AlertDeduper


class LatencyMonitor:
    """
    Protocol neutral latency monitor.

    It works on FlowRecord objects only, never on raw protocol packets.

    Main concepts:
      window_seconds
        How far back we look when computing stats

      threshold_ms
        Offender threshold applied to p95 latency

      min_samples
        Avoid noise, do not alert on tiny sample sets

      cooldown_seconds
        Prevent alert spam, one alert per flow key per cooldown interval
    """

    def __init__(
        self,
        threshold_ms: float = 150.0,
        window_seconds: int = 300,
        min_samples: int = 5,
        cooldown_seconds: int = 120,
    ):
        self.threshold_ms = float(threshold_ms)
        self.window_seconds = int(window_seconds)
        self.min_samples = int(min_samples)
        self.deduper = AlertDeduper(cooldown_seconds=int(cooldown_seconds))

    def set_thresholds(
        self,
        threshold_ms: Optional[float] = None,
        window_seconds: Optional[int] = None,
        min_samples: Optional[int] = None,
        cooldown_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Update monitor parameters at runtime.
        Exposed as an MCP tool by the core server.
        """
        if threshold_ms is not None:
            self.threshold_ms = float(threshold_ms)
        if window_seconds is not None:
            self.window_seconds = int(window_seconds)
        if min_samples is not None:
            self.min_samples = int(min_samples)
        if cooldown_seconds is not None:
            self.deduper.cooldown_seconds = int(cooldown_seconds)

        return {
            "threshold_ms": self.threshold_ms,
            "window_seconds": self.window_seconds,
            "min_samples": self.min_samples,
            "cooldown_seconds": self.deduper.cooldown_seconds,
        }

    def analyze(self, flows: List[FlowRecord]) -> Dict[str, Any]:
        """
        Compute latency stats per flow key.

        Stats computed:
          avg latency
          p50 latency
          p95 latency
          max latency

        Offenders:
          p95 >= threshold_ms and samples >= min_samples
        """
        groups: Dict[str, List[float]] = defaultdict(list)

        for f in flows:
            groups[f.key()].append(float(f.latency_ms))

        offenders: List[Dict[str, Any]] = []
        summary: List[Dict[str, Any]] = []

        for key, vals in groups.items():
            if not vals:
                continue

            vals_sorted = sorted(vals)

            # Percentiles computed by index into sorted list.
            # At higher scale, use streaming percentile structures.
            p50 = vals_sorted[int(0.50 * (len(vals_sorted) - 1))]
            p95 = vals_sorted[int(0.95 * (len(vals_sorted) - 1))]
            avg = sum(vals) / len(vals)

            row = {
                "flow": key,
                "samples": len(vals),
                "avg_ms": avg,
                "p50_ms": p50,
                "p95_ms": p95,
                "max_ms": max(vals),
            }
            summary.append(row)

            if len(vals) >= self.min_samples and p95 >= self.threshold_ms:
                offenders.append(row)

        offenders.sort(key=lambda r: r["p95_ms"], reverse=True)
        summary.sort(key=lambda r: r["p95_ms"], reverse=True)

        return {
            "window_seconds": self.window_seconds,
            "threshold_ms": self.threshold_ms,
            "min_samples": self.min_samples,
            "offenders": offenders[:50],
            "top": summary[:50],
        }

    def build_alerts(self, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Convert offenders to alert objects and apply dedupe.

        Alerts are returned to the caller. You can add an alert sink later:
          Slack webhook
          PagerDuty
          Email
          Generic HTTP endpoint
        """
        alerts: List[Dict[str, Any]] = []

        for off in analysis.get("offenders", []):
            key = off["flow"]

            if self.deduper.should_alert(key):
                alerts.append(
                    {
                        "type": "latency_threshold",
                        "flow": key,
                        "p95_ms": off["p95_ms"],
                        "threshold_ms": analysis["threshold_ms"],
                        "samples": off["samples"],
                        "ts": time.time(),
                        "message": (
                            f"p95 latency {off['p95_ms']:.1f} ms exceeds "
                            f"threshold {analysis['threshold_ms']:.1f} ms"
                        ),
                    }
                )

        return alerts
