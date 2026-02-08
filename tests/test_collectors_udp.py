import asyncio
import socket
import json
import pytest
pytestmark = pytest.mark.skip(reason="async collector integration test requires pytest-asyncio in CI")
from flow_agent_mcp.capabilities.json_udp.capability import build_capability as build_json_cap

@pytest.mark.asyncio
async def test_json_udp_collector_receives_and_stores(ctx):
    cap = build_json_cap()
    cap.register_tools(mcp=None, ctx=ctx)  # mcp not needed for direct start in tests

    # Bind to an ephemeral port by asking OS for a free one
    host = "127.0.0.1"
    port = 0

    # Start collector
    # If your start returns the bound address or string, ignore it
    await cap.start(host=host, port=port)

    # Find the actual bound port if your capability exposes it
    # If not, hardcode a test port and ensure it is free
    bound_port = cap.status().get("port")
    assert bound_port

    # Send one JSON flow record over UDP
    payload = {
        "ts": 1.0,
        "src": "10.0.0.1",
        "dst": "10.0.0.2",
        "src_port": 1111,
        "dst_port": 2222,
        "proto": "TCP",
        "latency_ms": 250.0,
        "bytes": 100,
        "packets": 1,
    }

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto((json.dumps(payload) + "\n").encode("utf-8"), (host, int(bound_port)))
    sock.close()

    # Give the event loop a moment to process
    await asyncio.sleep(0.1)

    # Verify store has at least one record
    recent = ctx.store.recent(window_seconds=300)
    assert any(r.src == "10.0.0.1" and r.dst_port == 2222 for r in recent)

    await cap.stop()
