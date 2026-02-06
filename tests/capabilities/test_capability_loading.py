from flow_agent_mcp.core.registry import CapabilityRegistry


def test_load_all_capabilities():
    reg = CapabilityRegistry()
    reg.load_from_import_paths(
        [
            "flow_agent_mcp.capabilities.json_udp.capability:build_capability",
            "flow_agent_mcp.capabilities.sflow_udp.capability:build_capability",
            "flow_agent_mcp.capabilities.netflow_udp.capability:build_capability",
            "flow_agent_mcp.capabilities.jflow_udp.capability:build_capability",
            "flow_agent_mcp.capabilities.ipfix_udp.capability:build_capability",
        ]
    )

    names = reg.list()
    assert "json_udp" in names
    assert "sflow_udp" in names
    assert "netflow_udp" in names
    assert "jflow_udp" in names
    assert "ipfix_udp" in names
