from __future__ import annotations
import time
from collections import deque
from typing import Deque, List
from .models import FlowRecord


class FlowStore:
    """
    In memory storage for recent FlowRecord objects.

    Why a deque:
      It is fast for append
      It enforces a max size to avoid unbounded memory growth

    Important:
      recent(seconds) scans current buffer. That is fine for a starter.
      At high scale you can replace this with:
        a time bucket store
        a database
        a streaming analytics component
    """

    def __init__(self, maxlen: int = 200_000):
        self._flows: Deque[FlowRecord] = deque(maxlen=maxlen)

    def add_many(self, flows: List[FlowRecord]) -> None:
        """
        Capabilities call this with decoded FlowRecord objects.
        """
        for f in flows:
            self._flows.append(f)

    def recent(self, seconds: int = 300) -> List[FlowRecord]:
        """
        Return flows newer than now minus seconds.
        """
        cutoff = time.time() - seconds
        return [f for f in self._flows if f.ts >= cutoff]
