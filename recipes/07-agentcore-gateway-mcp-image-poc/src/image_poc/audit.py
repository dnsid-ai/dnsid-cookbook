from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AuditError(Exception):
    pass


class AuditStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def record(self, event: dict[str, Any]) -> str:
        audit_id = uuid.uuid4().hex
        record = {
            "audit_id": audit_id,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            **event,
        }
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as file:
                file.write(json.dumps(record, sort_keys=True) + "\n")
        except OSError as exc:
            raise AuditError(f"Failed to write local audit record: {exc}") from exc
        return audit_id
