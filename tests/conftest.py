import time
import pytest

from flow_agent_mcp.core.store import FlowStore
from flow_agent_mcp.core.monitor import LatencyMonitor
from flow_agent_mcp.core.capability_base import CapabilityContext

@pytest.fixture
def store():
    return FlowStore(max_records=10_000)

@pytest.fixture
def monitor():
    m = LatencyMonitor()
    m.set_thresholds(threshold_ms=150.0, window_seconds=60, min_samples=1, cooldown_seconds=0)
    return m

@pytest.fixture
def ctx(store, monitor):
    def log(msg: str) -> None:
        pass
    return CapabilityContext(store=store, monitor=monitor, log=log)

@pytest.fixture
def now_ts():
    return time.time()
