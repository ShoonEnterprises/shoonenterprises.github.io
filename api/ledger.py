"""Append-only JSONL metrics ledger + tax-export stub.

Every intake, authorization, task lifecycle event and settlement is appended.
Sandbox tax export is a stub: it proves the pipeline shape (per-transaction
rows) with $0.00 values and a clear SANDBOX label — there is no real income.
"""

from __future__ import annotations

import datetime as dt
import json
import threading
from pathlib import Path
from typing import Any, Dict, List


class Ledger:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch(exist_ok=True)

    def append(self, record: Dict[str, Any]) -> None:
        entry = {
            "ts_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "sandbox": True,
            **record,
        }
        line = json.dumps(entry, separators=(",", ":"))
        with self._lock:
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")

    def all(self) -> List[Dict[str, Any]]:
        with self._lock:
            lines = self._path.read_text(encoding="utf-8").splitlines()
        out = []
        for line in lines:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return out

    def tail(self, limit: int = 50) -> List[Dict[str, Any]]:
        return self.all()[-limit:]

    def find_task(self, task_id: str) -> List[Dict[str, Any]]:
        return [r for r in self.all() if r.get("task_id") == task_id]
