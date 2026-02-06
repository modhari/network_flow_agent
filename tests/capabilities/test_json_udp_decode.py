import json
import time
from flow_agent_mcp.capabilities.json_udp.capability import JsonUdpCapability


def test_json_udp_decode_single_flow():
    cap = JsonUdpCapability()
    now = time.time()
    msg = {
        "ts": now,
        "src": "10.0.0.1",
        "dst": "10.0.0.2",
        "src_port": 1111,
        "dst_port": 443,
        "proto": "TCP",
        "latency_ms": 123.0,
        "bytes": 10,
        "packets": 1,
    }
    flows = cap._decode(json.dumps(msg).encode())
    assert len(flows) == 1
    assert flows[0].latency_ms == 123.0
