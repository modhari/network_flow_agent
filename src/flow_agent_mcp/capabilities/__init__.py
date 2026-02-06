"""
Capabilities are pluggable modules that can be loaded at runtime.

Each capability must expose a build_capability factory in its capability module.
"""

__all__ = [
    "json_udp",
    "sflow_udp",
    "netflow_udp",
    "jflow_udp",
    "ipfix_udp",
]
