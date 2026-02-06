# flow_agent_mcp

A protocol neutral MCP server for flow ingestion and latency monitoring.

Core does not depend on any one flow protocol.
Collectors and decoders are implemented as pluggable capabilities:
json_udp, sflow_udp, netflow_udp, jflow_udp, ipfix_udp.

## Install

pip install -e ".[dev]"

## Run server with selected capabilities

Choose which capabilities to load using FLOW_CAPABILITIES.

Example load json_udp plus sflow_udp:

export FLOW_CAPABILITIES='[
  "flow_agent_mcp.capabilities.json_udp.capability:build_capability",
  "flow_agent_mcp.capabilities.sflow_udp.capability:build_capability"
]'

python -m flow_agent_mcp.cli.run_server

## Send test samples for json_udp

python scripts/send_json_udp_samples.py

## Core MCP tools

list_capabilities
capability_status
set_thresholds
analyze_latency
monitor_once

## Capability MCP tools

start_collection
stop_collection

Both tools accept a capability argument to select which plugin to control.
