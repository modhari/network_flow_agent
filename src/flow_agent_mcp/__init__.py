"""
flow_agent_mcp

Protocol neutral MCP server plus pluggable flow collection capabilities.

Core ideas
1. Capabilities ingest protocol specific flow exports
2. Decoders normalize into FlowRecord
3. Core monitor analyzes FlowRecord without knowing the source protocol
"""

__all__ = ["core", "capabilities", "cli"]
