from __future__ import annotations

from typing import List

from flow_agent_mcp.core.models import FlowRecord
from flow_agent_mcp.capabilities.netflow_udp.decoder import decode_netflow

# jFlow is commonly NetFlow v9 compatible in practice, so reuse the v9 logic.
# Keep a separate capability so you can add Juniper specific field mappings later.


def decode_jflow(data: bytes, exporter: str = "unknown") -> List[FlowRecord]:
    return decode_netflow(data, exporter=exporter)
