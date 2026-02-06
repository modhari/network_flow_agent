import time
from flow_agent_mcp.core.models import FlowRecord
from flow_agent_mcp.core.monitor import LatencyMonitor


def make_flow(lat_ms: float, ts: float):
    return FlowRecord(
        ts=ts,
        src="10.0.0.1",
        dst="10.0.0.2",
        src_port=1111,
        dst_port=443,
        proto="TCP",
        latency_ms=lat_ms,
        bytes=100,
        packets=1,
    )


def test_monitor_offender_detected():
    mon = LatencyMonitor(threshold_ms=150.0, min_samples=5)
    now = time.time()
    flows = [
        make_flow(10, now),
        make_flow(20, now),
        make_flow(30, now),
        make_flow(200, now),
        make_flow(220, now),
    ]
    analysis = mon.analyze(flows)
    assert len(analysis["offenders"]) == 1
