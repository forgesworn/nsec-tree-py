"""Purpose-string validation — PROTOCOL.md §3."""
from __future__ import annotations
from .errors import InvalidPurpose


def validate_purpose(purpose: str) -> None:
    raw = purpose.encode("utf-8")
    if len(raw) < 1:
        raise InvalidPurpose("purpose must be non-empty")
    if len(raw) > 255:
        raise InvalidPurpose("purpose must be <= 255 UTF-8 bytes")
    if b"\x00" in raw:
        raise InvalidPurpose("purpose must not contain null bytes")
    if purpose.strip() == "":
        raise InvalidPurpose("purpose must not be whitespace-only")
