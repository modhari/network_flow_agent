from __future__ import annotations
import asyncio
import socket
from typing import Any, Dict, Optional, List

from flow_agent_mcp.core.capability_base import Capability, CapabilityContext
from flow_agent_mcp.core.models import FlowRecord
from .decoder import decode_jflow


class JflowUdpCapability:
    """
    jFlow UDP capability.

    jFlow is Juniper branding for flow export, commonly NetFlow v9 compatible.
    We keep it as a separate capability so you can add Juniper specific behaviors:
      exporter quirks
      template handling differences
      custom fields mapping
    """

    name = "jflow_udp"

    def __init__(self):
        self._ctx: Optional[CapabilityContext] = None
        self._task: Optional[asyncio.Task] = None
        self._stop = asyncio.Event()
        self._running = False

        self._host = "0.0.0.0"
        self._port = 2055

        self._ingested = 0
        self._dropped = 0

    def register_tools(self, mcp: Any, ctx: CapabilityContext) -> None:
        self._ctx = ctx

        @mcp.tool()
        async def start_collection(capability: str, host: str = "0.0.0.0", port: int = 2055) -> str:
            if capability != self.name:
                return f"wrong capability, expected {self.name}"
            return await self.start(host, port)

        @mcp.tool()
        async def stop_collection(capability: str) -> str:
            if capability != self.name:
                return f"wrong capability, expected {self.name}"
            return await self.stop()

    async def start(self, host: str, port: int) -> str:
        if self._running:
            return "already running"
        self._host = host
        self._port = int(port)
        self._stop.clear()
        self._task = asyncio.create_task(self._run())
        self._running = True
        return f"jflow collector started on {host}:{port}"

    async def stop(self) -> str:
        if not self._running:
            return "not running"
        self._stop.set()
        if self._task:
            await self._task
        self._running = False
        return "stopped"

    async def _run(self) -> None:
        if not self._ctx:
            return

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        sock.bind((self._host, self._port))
        loop = asyncio.get_running_loop()

        try:
            while not self._stop.is_set():
                try:
                    data, _ = await loop.sock_recvfrom(sock, 65535)
                except Exception:
                    await asyncio.sleep(0.05)
                    continue

                flows: List[FlowRecord] = decode_jflow(data)

                if flows:
                    self._ctx.store.add_many(flows)
                    self._ingested += len(flows)
                else:
                    self._dropped += 1
        finally:
            sock.close()

    def status(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "running": self._running,
            "host": self._host,
            "port": self._port,
            "ingested": self._ingested,
            "dropped": self._dropped,
        }


def build_capability() -> Capability:
    return JflowUdpCapability()
