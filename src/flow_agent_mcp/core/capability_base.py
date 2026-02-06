from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Protocol


@dataclass
class CapabilityContext:
    """
    Shared runtime objects provided by the core server to each capability.

    store
      Shared FlowStore instance where capabilities write FlowRecord objects.

    monitor
      Shared LatencyMonitor instance. Capabilities usually do not need it,
      but it allows advanced plugins to expose helper tools if desired.

    log
      Simple logging function. Swap later for structured logging if you want.
    """

    store: Any
    monitor: Any
    log: Callable[[str], None]


class Capability(Protocol):
    """
    Required interface for a capability plugin.

    A capability is responsible for
    1. Registering MCP tools, like start_collection and stop_collection
    2. Ingesting data from a protocol source
    3. Decoding into FlowRecord and writing to ctx.store

    The core server never imports specific capabilities directly.
    It loads them via registry using import paths.
    """

    name: str

    def register_tools(self, mcp: Any, ctx: CapabilityContext) -> None:
        """
        Called once at server startup. Capabilities should register tools here.
        """
        ...

    def status(self) -> Dict[str, Any]:
        """
        Return quick health and counters. Must be fast and side effect free.
        """
        ...

    async def start(self, host: str, port: int) -> str:
        """
        Optional lifecycle method. Not all capabilities must implement it,
        but most collectors will.
        """
        ...

    async def stop(self) -> str:
        """
        Optional lifecycle method to stop collection tasks.
        """
        ...
