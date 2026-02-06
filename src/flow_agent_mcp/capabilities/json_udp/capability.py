from __future__ import annotations
import asyncio
import json
import socket
import time
from typing import Any, Dict, Optional, List

from flow_agent_mcp.core.capability_base import Capability, CapabilityContext
from flow_agent_mcp.core.models import FlowRecord


class JsonUdpCapability:
    """
    JSON over UDP capability.

    This is a practical testing capability. It lets you validate:
      MCP server loading
      tool control
      store ingestion
      monitor analysis
    without implementing any binary flow protocol decoder.

    The expected UDP payload:
      JSON object or list of JSON objects
      each object must include src, dst, latency_ms
    """

    name = "json_udp"

    def __init__(self):
        self._ctx: Optional[CapabilityContext] = None
        self._task: Optional[asyncio.Task] = None
        self._stop = asyncio.Event()
        self._running = False

        self._host = "0.0.0.0"
        self._port = 6343

        self._ingested = 0
        self._dropped = 0

    def register_tools(self, mcp: Any, ctx: CapabilityContext) -> None:
        self._ctx = ctx

        @mcp.tool()
        async def start_collection(capability: str, host: str = "0.0.0.0", port: int = 6343) -> str:
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
        return f"json udp collector started on {host}:{port}"

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

                flows = self._decode(data)
                if flows:
                    self._ctx.store.add_many(flows)
                    self._ingested += len(flows)
                else:
                    self._dropped += 1
        finally:
            sock.close()

    def _decode(self, data: bytes) -> List[FlowRecord]:
        """
        Decode JSON payload into FlowRecord objects.

        If the payload is invalid JSON or missing required fields,
        we return an empty list which the collector counts as dropped.
        """
        try:
            obj = json.loads(data.decode("utf-8", errors="ignore").strip())
        except Exception:
            return []

        def to_flow(d: Dict[str, Any]) -> Optional[FlowRecord]:
            try:
                return FlowRecord(
                    ts=float(d.get("ts", time.time())),
                    src=str(d["src"]),
                    dst=str(d["dst"]),
                    src_port=int(d.get("src_port", 0)),
                    dst_port=int(d.get("dst_port", 0)),
                    proto=str(d.get("proto", "TCP")),
                    latency_ms=float(d["latency_ms"]),
                    bytes=int(d.get("bytes", 0)),
                    packets=int(d.get("packets", 0)),
                )
            except Exception:
                return None

        flows: List[FlowRecord] = []

        if isinstance(obj, list):
            for item in obj:
                if isinstance(item, dict):
                    f = to_flow(item)
                    if f:
                        flows.append(f)
        elif isinstance(obj, dict):
            f = to_flow(obj)
            if f:
                flows.append(f)

        return flows

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
    return JsonUdpCapability()
