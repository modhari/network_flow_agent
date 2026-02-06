from __future__ import annotations
import os
import json
from flow_agent_mcp.core.server import FlowMCPServer


def main() -> None:
    """
    Load capabilities from FLOW_CAPABILITIES env var.

    Example:
      export FLOW_CAPABILITIES='[
        "flow_agent_mcp.capabilities.netflow_udp.capability:build_capability",
        "flow_agent_mcp.capabilities.ipfix_udp.capability:build_capability"
      ]'
      python -m flow_agent_mcp.cli.run_server
    """
    raw = os.environ.get("FLOW_CAPABILITIES", "[]")
    imports = json.loads(raw)

    server = FlowMCPServer(capability_imports=imports)
    server.run()


if __name__ == "__main__":
    main()
