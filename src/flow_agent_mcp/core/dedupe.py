from __future__ import annotations
import time
from typing import Dict


class AlertDeduper:
    """
    Deduplicates alerts by key for a cooldown interval.

    Example:
      If a flow is continuously bad, you do not want one alert per monitor pass.
      You want an alert at most once per cooldown interval per flow key.
    """

    def __init__(self, cooldown_seconds: int = 120):
        self.cooldown_seconds = cooldown_seconds
        self.last_alert_ts: Dict[str, float] = {}

    def should_alert(self, key: str) -> bool:
        """
        True means emit an alert now.
        False means suppress due to cooldown.
        """
        now = time.time()
        last = self.last_alert_ts.get(key)

        if last is None:
            self.last_alert_ts[key] = now
            return True

        if now - last >= self.cooldown_seconds:
            self.last_alert_ts[key] = now
            return True

        return False
