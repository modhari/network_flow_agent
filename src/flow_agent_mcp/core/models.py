from __future__ import annotations
from dataclasses import dataclass


@dataclass
class FlowRecord:
    """
    Normalized flow record that all capabilities must output.

    This decouples monitoring from protocol specifics.

    Fields:
      ts
        Unix time in seconds, when the flow was observed or received.

      src, dst
        IP addresses as strings.

      src_port, dst_port
        Transport layer ports, use 0 if unknown.

      proto
        Protocol string such as TCP, UDP, ICMP.

      latency_ms
        Latency value in milliseconds. Your pipeline defines what this means.
        Monitor compares this value to thresholds.

      bytes, packets
        Optional counters for triage or future analysis.
    """

    ts: float
    src: str
    dst: str
    src_port: int
    dst_port: int
    proto: str
    latency_ms: float
    bytes: int = 0
    packets: int = 0

    def key(self) -> str:
        """
        Group key used by monitor. Similar to a 5 tuple identifier.
        """
        return f"{self.src}:{self.src_port}->{self.dst}:{self.dst_port}/{self.proto}"
