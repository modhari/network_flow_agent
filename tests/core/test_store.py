import time
from flow_agent_mcp.core.models import FlowRecord
from flow_agent_mcp.core.store import FlowStore


def test_store_recent_filters_by_time():
    store = FlowStore(maxlen=10)
    now = time.time()

    old = FlowRecord(ts=now - 1000, src="a", dst="b", src_port=1, dst_port=2, proto="TCP", latency_ms=1.0)
    new = FlowRecord(ts=now, src="a", dst="b", src_port=1, dst_port=2, proto="TCP", latency_ms=1.0)

    store.add_many([old, new])
    recent = store.recent(seconds=10)

    assert len(recent) == 1
    assert recent[0].ts == new.ts
