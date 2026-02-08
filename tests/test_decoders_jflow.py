from flow_agent_mcp.capabilities.jflow_udp.decoder import decode_jflow
from flow_agent_mcp.capabilities.netflow_udp.decoder import decode_netflow
from tests.test_decoders_netflow import _build_netflow_v9_template_and_data

def test_jflow_delegates_to_netflow():
    data, _ = _build_netflow_v9_template_and_data()
    a = decode_jflow(data, exporter="1.2.3.4")
    b = decode_netflow(data, exporter="1.2.3.4")
    assert len(a) == len(b) == 1
    assert a[0].src == b[0].src
