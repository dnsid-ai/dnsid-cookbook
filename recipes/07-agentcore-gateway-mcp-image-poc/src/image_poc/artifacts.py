from __future__ import annotations

import os
import uuid
from dataclasses import dataclass
from pathlib import Path


class ArtifactError(Exception):
    pass


@dataclass(frozen=True)
class Artifact:
    artifact_id: str
    artifact_path: Path
    artifact_url: str


class ArtifactStore:
    def __init__(self, root: Path) -> None:
        self.root = root

    def write_image(self, image_bytes: bytes) -> Artifact:
        self.root.mkdir(parents=True, exist_ok=True)
        artifact_id = uuid.uuid4().hex
        final_path = self.root / f"{artifact_id}.png"
        temp_path = self.root / f".{artifact_id}.tmp"
        try:
            temp_path.write_bytes(image_bytes)
            os.replace(temp_path, final_path)
        except OSError as exc:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise ArtifactError(f"Failed to write image artifact: {exc}") from exc
        return Artifact(
            artifact_id=artifact_id,
            artifact_path=final_path,
            artifact_url=f"/artifacts/{artifact_id}.png",
        )

    def path_for(self, artifact_id: str) -> Path:
        try:
            parsed = uuid.UUID(artifact_id)
        except ValueError as exc:
            raise ArtifactError("Invalid artifact ID.") from exc
        if parsed.hex != artifact_id:
            raise ArtifactError("Invalid artifact ID.")
        path = self.root / f"{artifact_id}.png"
        try:
            path.resolve().relative_to(self.root.resolve())
        except ValueError as exc:
            raise ArtifactError("Invalid artifact path.") from exc
        return path
