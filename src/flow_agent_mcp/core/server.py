from __future__ import annotations
from typing import Any, Dict, List, Optional

from mcp.server.fastmcp import FastMCP

from .store import FlowStore
from .monitor import LatencyMonitor
from .capability_base import CapabilityContext
from .registry import CapabilityRegistry


class FlowMCPServer:
    """
    Protocol neutral MCP server.

    Responsibilities:
      Load configured capabilities
      Register capability tools
      Expose core monitoring tools
      Provide shared store and monitor to all capabilities
    """

    def __init__(self, capability_imports: List[str]):
        self.store = FlowStore()
        self.monitor = LatencyMonitor()
        self.registry = CapabilityRegistry()
        self.mcp = FastMCP("flow_agent_mcp")

        self._load_capabilities(capability_imports)
        self._register_core_tools()

    def _log(self, msg: str) -> None:
        print(msg)

    def _load_capabilities(self, imports: List[str]) -> None:
        self.registry.load_from_import_paths(imports)
        ctx = CapabilityContext(store=self.store, monitor=self.monitor, log=self._log)

        for name in self.registry.list():
            cap = self.registry.get(name)
            cap.register_tools(self.mcp, ctx)

    def _register_core_tools(self) -> None:
        @self.mcp.tool()
        def list_capabilities() -> List[str]:
            return self.registry.list()

        @self.mcp.tool()
        def capability_status(name: str) -> Dict[str, Any]:
            cap = self.registry.get(name)
            return cap.status()

        @self.mcp.tool()
        def set_thresholds(
            threshold_ms: Optional[float] = None,
            window_seconds: Optional[int] = None,
            min_samples: Optional[int] = None,
            cooldown_seconds: Optional[int] = None,
        ) -> Dict[str, Any]:
            return self.monitor.set_thresholds(
                threshold_ms=threshold_ms,
                window_seconds=window_seconds,
                min_samples=min_samples,
                cooldown_seconds=cooldown_seconds,
            )

        @self.mcp.tool()
        def analyze_latency(seconds: Optional[int] = None) -> Dict[str, Any]:
            window = int(seconds) if seconds is not None else self.monitor.window_seconds
            flows = self.store.recent(seconds=window)
            return self.monitor.analyze(flows)

        @self.mcp.tool()
        def monitor_once() -> Dict[str, Any]:
            flows = self.store.recent(seconds=self.monitor.window_seconds)
            analysis = self.monitor.analyze(flows)
            alerts = self.monitor.build_alerts(analysis)
            return {"alerts": alerts, "analysis": analysis, "alert_count": len(alerts)}

    def run(self) -> None:
        self.mcp.run()
