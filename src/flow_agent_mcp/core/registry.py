from __future__ import annotations
import importlib
from dataclasses import dataclass
from typing import Dict, List
from .capability_base import Capability


@dataclass
class LoadedCapability:
    """
    Wrapper for a loaded capability instance.
    """
    name: str
    instance: Capability


class CapabilityRegistry:
    """
    Holds loaded capability instances.

    Important:
      Core never imports protocol modules directly.
      This registry loads modules based on import strings.

    Import string format:
      "some.module.path:factory_function"

    Example:
      "flow_agent_mcp.capabilities.sflow_udp.capability:build_capability"
    """

    def __init__(self):
        self._caps: Dict[str, LoadedCapability] = {}

    def register(self, cap: Capability) -> None:
        if cap.name in self._caps:
            raise ValueError(f"duplicate capability name {cap.name}")
        self._caps[cap.name] = LoadedCapability(name=cap.name, instance=cap)

    def get(self, name: str) -> Capability:
        if name not in self._caps:
            raise KeyError(f"capability not loaded {name}")
        return self._caps[name].instance

    def list(self) -> List[str]:
        return sorted(self._caps.keys())

    def load_from_import_paths(self, import_paths: List[str]) -> None:
        for path in import_paths:
            module_path, factory_name = path.split(":")
            module = importlib.import_module(module_path)
            factory = getattr(module, factory_name)
            cap = factory()
            self.register(cap)
