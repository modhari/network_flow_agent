from __future__ import annotations

import time
from dataclasses import asdict
from typing import Any, Dict, List, Optional, Tuple

from flow_agent_mcp.core.capability_base import CapabilityBase, CapabilityContext
from flow_agent_mcp.core.models import FlowRecord

from .baseline import AnomalyEvent, BaselineModel, compute_window_stats
from .shift import ShiftEvent, ShiftModel


def _safe_getattr(obj: Any, name: str) -> Optional[str]:
    v = getattr(obj, name, None)
    if v is None:
        return None
    return str(v)


def _key_builder(flow: FlowRecord, mode: str) -> str:
    """
    Choose how to group flows for baseline and shift logic.

    Modes:
      exporter: use flow.exporter if present
      src: use flow.src
      dst: use flow.dst
      pair: src->dst
      proto: protocol
    """
    if mode == "exporter":
        return _safe_getattr(flow, "exporter") or "exporter:unknown"
    if mode == "src":
        return f"src:{flow.src}"
    if mode == "dst":
        return f"dst:{flow.dst}"
    if mode == "pair":
        return f"pair:{flow.src}->{flow.dst}"
    if mode == "proto":
        return f"proto:{flow.proto}"
    return f"all:{mode}"


class BaselineAnomalyCapability(CapabilityBase):
    """
    Protocol neutral capability.

    Reads FlowStore recent window and produces:
      - anomaly events based on baseline deviation
      - shift events based on distribution change

    This adds value for operators without touching collectors.
    """

    name = "baseline_anomaly"

    def __init__(self) -> None:
        super().__init__()
        self._baseline = BaselineModel()
        self._shift = ShiftModel()

        # Defaults are conservative.
        self._window_seconds = 60
        self._min_samples_per_key = 20
        self._alpha = 0.15
        self._z_threshold = 4.0
        self._min_updates = 10

        self._shift_threshold = 0.7
        self._shift_min_total = 200.0

        self._group_mode = "exporter"
        self._cooldown_seconds = 120
        self._last_alert_ts: Dict[str, float] = {}

    def configure(
        self,
        window_seconds: int = 60,
        min_samples_per_key: int = 20,
        alpha: float = 0.15,
        z_threshold: float = 4.0,
        min_updates: int = 10,
        group_mode: str = "exporter",
        cooldown_seconds: int = 120,
        shift_threshold: float = 0.7,
        shift_min_total: float = 200.0,
    ) -> Dict[str, Any]:
        self._window_seconds = int(window_seconds)
        self._min_samples_per_key = int(min_samples_per_key)
        self._alpha = float(alpha)
        self._z_threshold = float(z_threshold)
        self._min_updates = int(min_updates)
        self._group_mode = str(group_mode)
        self._cooldown_seconds = int(cooldown_seconds)
        self._shift_threshold = float(shift_threshold)
        self._shift_min_total = float(shift_min_total)

        return {
            "ok": True,
            "window_seconds": self._window_seconds,
            "min_samples_per_key": self._min_samples_per_key,
            "alpha": self._alpha,
            "z_threshold": self._z_threshold,
            "min_updates": self._min_updates,
            "group_mode": self._group_mode,
            "cooldown_seconds": self._cooldown_seconds,
            "shift_threshold": self._shift_threshold,
            "shift_min_total": self._shift_min_total,
        }

    def _in_cooldown(self, key: str) -> bool:
        last = self._last_alert_ts.get(key, 0.0)
        return (time.time() - last) < self._cooldown_seconds

    def _mark_alert(self, key: str) -> None:
        self._last_alert_ts[key] = time.time()

    def analyze_once(self, ctx: CapabilityContext) -> Dict[str, Any]:
        flows = ctx.store.recent(seconds=self._window_seconds)

        # Group latencies by key
        lat_by_key: Dict[str, List[float]] = {}
        count_by_key: Dict[str, float] = {}

        for f in flows:
            # Not all flows will have latency_ms. Skip if missing.
            latency = getattr(f, "latency_ms", None)
            if latency is None:
                continue

            k = _key_builder(f, self._group_mode)
            lat_by_key.setdefault(k, []).append(float(latency))
            count_by_key[k] = count_by_key.get(k, 0.0) + 1.0

        anomalies: List[Dict[str, Any]] = []
        for key, lats in lat_by_key.items():
            if len(lats) < self._min_samples_per_key:
                continue

            stats = compute_window_stats(lats)
            p50 = float(stats["p50"])
            p95 = float(stats["p95"])

            # Update baseline first, then detect. This gives smoother steady state.
            p50_pt = self._baseline.update(key, "p50_ms", p50, alpha=self._alpha)
            p95_pt = self._baseline.update(key, "p95_ms", p95, alpha=self._alpha)

            # Detect anomalies on current window values
            a1 = self._baseline.detect_anomaly(
                key=key,
                metric="p50_ms",
                current_value=p50,
                z_threshold=self._z_threshold,
                min_updates=self._min_updates,
            )
            a2 = self._baseline.detect_anomaly(
                key=key,
                metric="p95_ms",
                current_value=p95,
                z_threshold=self._z_threshold,
                min_updates=self._min_updates,
            )

            for metric, current, det in [
                ("p50_ms", p50, a1),
                ("p95_ms", p95, a2),
            ]:
                if det is None:
                    continue

                mean, std, z = det
                alert_key = f"anomaly:{key}:{metric}"

                if self._in_cooldown(alert_key):
                    continue

                ev = AnomalyEvent(
                    key=key,
                    metric=metric,
                    current=current,
                    baseline_mean=mean,
                    baseline_std=std,
                    zscore=z,
                    window_seconds=self._window_seconds,
                    sample_count=len(lats),
                    ts=time.time(),
                )
                anomalies.append(asdict(ev))
                self._mark_alert(alert_key)

        # Traffic shift detection on distribution of key counts
        shift_event: ShiftEvent | None = self._shift.update_and_detect(
            dimension=f"count_by_{self._group_mode}",
            counts=count_by_key,
            threshold=self._shift_threshold,
            min_total=self._shift_min_total,
            window_seconds=self._window_seconds,
        )

        shift: Optional[Dict[str, Any]] = None
        if shift_event is not None:
            alert_key = f"shift:{shift_event.dimension}"
            if not self._in_cooldown(alert_key):
                shift = {
                    "dimension": shift_event.dimension,
                    "distance": shift_event.distance,
                    "window_seconds": shift_event.window_seconds,
                    "old_top": shift_event.old_top,
                    "new_top": shift_event.new_top,
                    "ts": shift_event.ts,
                }
                self._mark_alert(alert_key)

        return {
            "ok": True,
            "group_mode": self._group_mode,
            "window_seconds": self._window_seconds,
            "keys_seen": len(lat_by_key),
            "anomalies": anomalies,
            "shift": shift,
        }

    def register_tools(self, mcp: Any, ctx: CapabilityContext) -> None:
        """
        Expose this capability as MCP tools.

        Tools:
          baseline_configure
          baseline_analyze_once
        """
        if mcp is None:
            # Allows direct use in unit tests without an MCP server object.
            return

        @mcp.tool()
        def baseline_configure(
            window_seconds: int = 60,
            min_samples_per_key: int = 20,
            alpha: float = 0.15,
            z_threshold: float = 4.0,
            min_updates: int = 10,
            group_mode: str = "exporter",
            cooldown_seconds: int = 120,
            shift_threshold: float = 0.7,
            shift_min_total: float = 200.0,
        ) -> Dict[str, Any]:
            return self.configure(
                window_seconds=window_seconds,
                min_samples_per_key=min_samples_per_key,
                alpha=alpha,
                z_threshold=z_threshold,
                min_updates=min_updates,
                group_mode=group_mode,
                cooldown_seconds=cooldown_seconds,
                shift_threshold=shift_threshold,
                shift_min_total=shift_min_total,
            )

        @mcp.tool()
        def baseline_analyze_once() -> Dict[str, Any]:
            return self.analyze_once(ctx)
