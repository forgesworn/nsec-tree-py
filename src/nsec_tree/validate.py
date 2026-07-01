"""Purpose-string validation — PROTOCOL.md §3."""
from __future__ import annotations
import re

from .errors import InvalidPurpose

_PROOF_UNSAFE = re.compile(r"[\x00-\x1f\x7f|]")  # C0/DEL control chars or the '|' delimiter


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


def validate_proof_purpose(purpose: str) -> None:
    """Stricter validation for a purpose embedded in a linkage-proof
    attestation: the §5 format is pipe-delimited, so '|' and control
    characters must be rejected. Derivation itself (§2/§3) is unaffected.
    """
    validate_purpose(purpose)
    if _PROOF_UNSAFE.search(purpose):
        raise InvalidPurpose('proof purpose must not contain "|" or control characters')
