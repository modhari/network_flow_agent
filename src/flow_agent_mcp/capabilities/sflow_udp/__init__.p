"""
sflow_udp capability.

Collector receives sFlow v5 datagrams over UDP and decodes flow samples
into FlowRecord objects.
"""

__all__ = ["capability", "decoder"]
