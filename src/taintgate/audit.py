from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from .models import Decision


class JsonlAuditLog:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def write(self, decision: Decision) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **asdict(decision),
            "action": decision.action.value,
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, default=str, separators=(",", ":")) + "\n")
