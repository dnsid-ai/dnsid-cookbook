from __future__ import annotations

from dataclasses import dataclass
from typing import Any


LOCAL_TEST_AUTH_MODE = "local-test"
LOCAL_TEST_WARNING = (
    "Local-test fallback: this browser path calls local Bedrock directly; "
    "use Gateway mode for DNSid + AgentCore proof."
)

STYLE_PROMPTS = {
    "product": "clean product render, crisp edges, studio lighting",
    "illustration": "modern editorial illustration, crisp shapes, balanced colors",
    "cinematic": "cinematic lighting, shallow depth of field, polished composition",
    "natural": "natural lighting, realistic textures, balanced composition",
}
SIZE_ASPECT_RATIOS = {
    "1024x1024": "1:1",
}
MAX_PROMPT_CHARS = 1000


class ValidationError(Exception):
    def __init__(self, message: str, field: str | None = None) -> None:
        super().__init__(message)
        self.field = field


@dataclass(frozen=True)
class GenerateRequest:
    prompt: str
    style: str
    size: str

    @property
    def styled_prompt(self) -> str:
        style_prompt = STYLE_PROMPTS[self.style]
        return f"{self.prompt}. Style: {style_prompt}."

    @property
    def aspect_ratio(self) -> str:
        return SIZE_ASPECT_RATIOS[self.size]


def validate_generate_payload(payload: dict[str, Any]) -> GenerateRequest:
    prompt = payload.get("prompt")
    if not isinstance(prompt, str) or not prompt.strip():
        raise ValidationError("Prompt is required.", "prompt")
    prompt = " ".join(prompt.strip().split())
    if len(prompt) > MAX_PROMPT_CHARS:
        raise ValidationError(
            f"Prompt must be {MAX_PROMPT_CHARS} characters or fewer.", "prompt"
        )

    style = payload.get("style", "product")
    if not isinstance(style, str) or style not in STYLE_PROMPTS:
        allowed = ", ".join(sorted(STYLE_PROMPTS))
        raise ValidationError(f"Style must be one of: {allowed}.", "style")

    size = payload.get("size", "1024x1024")
    if not isinstance(size, str) or size not in SIZE_ASPECT_RATIOS:
        allowed = ", ".join(sorted(SIZE_ASPECT_RATIOS))
        raise ValidationError(f"Size must be one of: {allowed}.", "size")

    return GenerateRequest(prompt=prompt, style=style, size=size)
