import time
from flow_agent_mcp.core.models import FlowRecord
from flow_agent_mcp.capabilities.baseline_anomaly.capability import BaselineAnomalyCapability


def _flow(latency_ms: float) -> FlowRecord:
    # FlowRecord already exists in your repo. We set fields that your model supports.
    # If FlowRecord does not include exporter or latency_ms, tell me and I will adjust.
    return FlowRecord(
        ts=time.time(),
        src="10.0.0.1",
        dst="10.0.0.2",
        src_port=1234,
        dst_port=443,
        proto="TCP",
        latency_ms=latency_ms,
        packets=1,
        bytes=100,
    )

def test_baseline_anomaly_detects_spike(store, monitor, ctx):
    cap = BaselineAnomalyCapability()
    cap.configure(
        window_seconds=60,
        min_samples_per_key=20,
        alpha=0.2,
        z_threshold=3.0,
        min_updates=5,
        group_mode="pair",
        cooldown_seconds=0,
        shift_threshold=0.9,
        shift_min_total=1000,
    )

    # Build stable baseline
    base = [_flow(20.0) for _ in range(60)]
    ctx.store.add_many(base)

    # Run a few analyze passes to establish baseline updates
    for _ in range(6):
        out = cap.analyze_once(ctx)
        assert out["ok"] is True

    # Inject spike
    spike = [_flow(200.0) for _ in range(60)]
    ctx.store.add_many(spike)

    out = cap.analyze_once(ctx)
    anomalies = out["anomalies"]
    assert len(anomalies) >= 1
    assert any(a["metric"] in ("p95_ms", "p50_ms") for a in anomalies)


def test_traffic_shift_detects_distribution_change(store, monitor, ctx):
    cap = BaselineAnomalyCapability()
    cap.configure(
        window_seconds=60,
        min_samples_per_key=1,
        alpha=0.2,
        z_threshold=10.0,  # disable anomaly
        min_updates=999,
        group_mode="src",
        cooldown_seconds=0,
        shift_threshold=0.6,
        shift_min_total=50.0,
    )

    # window 1: mostly exporter A
    ctx.store.add_many([_flow(10.0, exporter="A") for _ in range(90)])
    ctx.store.add_many([_flow(10.0, exporter="B") for _ in range(10)])
    cap.analyze_once(ctx)  # prime previous distribution

    # window 2: mostly exporter B
    ctx.store.add_many([_flow(10.0, exporter="A") for _ in range(10)])
    ctx.store.add_many([_flow(10.0, exporter="B") for _ in range(90)])

    out = cap.analyze_once(ctx)
    assert out["shift"] is not None
    assert out["shift"]["distance"] >= 0.6
