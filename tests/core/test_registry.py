from flow_agent_mcp.core.registry import CapabilityRegistry


def test_registry_loads_capability_import():
    reg = CapabilityRegistry()
    reg.load_from_import_paths(
        ["flow_agent_mcp.capabilities.json_udp.capability:build_capability"]
    )
    assert "json_udp" in reg.list()
