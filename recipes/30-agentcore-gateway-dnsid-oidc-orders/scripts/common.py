from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise RuntimeError("deployment state missing; run make deploy")
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise RuntimeError("deployment state is invalid")
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
