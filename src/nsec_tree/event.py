"""NIP-78 (Kind 30078) event conversion — wrap/unwrap a linkage proof as a Nostr event.

Mirrors the TypeScript nsec-tree ``event.ts``. ``to_unsigned_event`` builds an
unsigned Nostr event carrying a :class:`~nsec_tree.proof.LinkageProof` in its tags,
which the application signs and publishes with its own Nostr library;
``from_event`` extracts the proof back out for verification.

``to_unsigned_event`` performs a structural sanity check (hex formats,
purpose/index consistency, and that ``proof.attestation`` matches the canonical
reconstruction) but does NOT verify the Schnorr signature — run
:func:`~nsec_tree.proof.verify_proof` for full cryptographic validation.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Any, Mapping

from .errors import NsecTreeError
from .proof import LinkageProof, canonical_attestation

# `\Z` (not `$`): Python's `$` also matches just before a trailing newline,
# whereas JavaScript's `$` does not. `\Z` anchors at the very end of the string,
# matching the TS reference exactly (rejects e.g. "0\n").
_MAX_INDEX = 0xFFFFFFFF
_HEX_KEY = re.compile(r"^[0-9a-f]{64}\Z")
_HEX_SIG = re.compile(r"^[0-9a-f]{128}\Z")
_STRICT_UINT = re.compile(r"^(?:0|[1-9]\d*)\Z")

NSEC_TREE_EVENT_KIND = 30078
"""NIP-78 application-specific data kind."""

NSEC_TREE_D_PREFIX = "nsec-tree:"
"""Namespace prefix for nsec-tree ``d`` tags."""


@dataclass(frozen=True)
class UnsignedEvent:
    """An unsigned Nostr event — the application signs and publishes this.

    Field names are the Nostr event JSON keys, so ``dataclasses.asdict(ev)``
    yields a ready-to-sign event object.
    """

    kind: int
    pubkey: str
    created_at: int
    tags: list[list[str]]
    content: str


def _single_tag_value(tags: list[list[str]], name: str) -> str | None:
    """Return the single value for tag ``name``, or ``None`` if absent.

    Raises on duplicates to prevent "duplicate tag smuggling", where a crafted
    event contains two copies of an nsec-tree tag and different verifiers pick
    different ones.  Non-list/tuple entries are silently skipped so a stray
    value in an untrusted event dict does not cause a TypeError.
    """
    matches = [t for t in tags if isinstance(t, (list, tuple)) and len(t) > 0 and t[0] == name]
    if len(matches) > 1:
        raise NsecTreeError(f'Duplicate "{name}" tag: event must contain at most one')
    if not matches:
        return None
    return matches[0][1] if len(matches[0]) > 1 else None


def _event_fields(event: UnsignedEvent | Mapping[str, Any]) -> tuple[str, list[list[str]]]:
    if isinstance(event, UnsignedEvent):
        return event.pubkey, event.tags
    try:
        pubkey = event["pubkey"]
        tags = event["tags"]
    except KeyError as exc:
        raise NsecTreeError(f"Event missing required field: {exc}") from exc
    if not isinstance(tags, list):
        raise NsecTreeError("Event 'tags' field must be a list")
    return pubkey, tags


def to_unsigned_event(proof: LinkageProof, created_at: int | None = None) -> UnsignedEvent:
    """Convert a :class:`LinkageProof` to an unsigned NIP-78 (Kind 30078) event.

    ``created_at`` defaults to the current Unix time; pass it explicitly for
    deterministic output. Raises :class:`NsecTreeError` if the proof is
    structurally malformed or its attestation does not match the canonical form.
    """
    expected = canonical_attestation(proof)
    if expected is None:
        raise NsecTreeError("Invalid proof: structurally malformed")
    if proof.attestation != expected:
        raise NsecTreeError("Invalid proof: attestation does not match canonical form")

    tags: list[list[str]] = [
        ["d", f"{NSEC_TREE_D_PREFIX}{proof.child_pubkey}"],
        ["p", proof.child_pubkey],
    ]
    if proof.purpose is not None and proof.index is not None:
        tags.append(["purpose", proof.purpose])
        tags.append(["index", str(proof.index)])
    tags.append(["attestation", proof.attestation])
    tags.append(["proof-sig", proof.signature])

    if created_at is None:
        created_at = int(time.time())

    return UnsignedEvent(
        kind=NSEC_TREE_EVENT_KIND,
        pubkey=proof.master_pubkey,
        created_at=created_at,
        tags=tags,
        content="",
    )


def from_event(event: UnsignedEvent | Mapping[str, Any]) -> LinkageProof:
    """Extract a :class:`LinkageProof` from a NIP-78 event's tags.

    Accepts either an :class:`UnsignedEvent` or a mapping with ``pubkey`` and
    ``tags`` (e.g. a Nostr event dict). Pass the result to
    :func:`~nsec_tree.proof.verify_proof` to check cryptographic validity. Raises
    :class:`NsecTreeError` if the event does not carry a well-formed nsec-tree proof.
    """
    pubkey, tags = _event_fields(event)

    d_value = _single_tag_value(tags, "d")
    if not d_value or not d_value.startswith(NSEC_TREE_D_PREFIX):
        raise NsecTreeError("Missing or invalid d tag: expected nsec-tree: prefix")

    attestation = _single_tag_value(tags, "attestation")
    if not attestation:
        raise NsecTreeError("Missing attestation tag")

    signature = _single_tag_value(tags, "proof-sig")
    if not signature:
        raise NsecTreeError("Missing proof-sig tag")

    child_pubkey = d_value[len(NSEC_TREE_D_PREFIX):]
    if not _HEX_KEY.match(child_pubkey):
        raise NsecTreeError("Invalid childPubkey in d tag: expected 64-char lowercase hex")

    p_value = _single_tag_value(tags, "p")
    if not p_value:
        raise NsecTreeError("Missing p tag")
    if p_value != child_pubkey:
        raise NsecTreeError("p tag does not match childPubkey in d tag")

    if not _HEX_KEY.match(pubkey):
        raise NsecTreeError("Invalid pubkey: expected 64-char lowercase hex")
    if not _HEX_SIG.match(signature):
        raise NsecTreeError("Invalid proof-sig: expected 128-char lowercase hex")

    purpose_value = _single_tag_value(tags, "purpose")
    index_value = _single_tag_value(tags, "index")

    if (purpose_value is None) != (index_value is None):
        raise NsecTreeError("purpose and index tags must both be present or both absent")

    index: int | None = None
    if index_value is not None:
        if not _STRICT_UINT.match(index_value):
            raise NsecTreeError(f"Invalid index tag: {index_value}")
        # Guard against CPython's int-parse limit (~4300 digits): a valid index
        # is at most 0xFFFFFFFF = 4294967295 (10 digits).
        if len(index_value) > 10:
            raise NsecTreeError(f"Index exceeds maximum ({_MAX_INDEX}): {index_value[:20]}...")
        index = int(index_value)
        if index > _MAX_INDEX:
            raise NsecTreeError(f"Index exceeds maximum ({_MAX_INDEX}): {index_value}")

    return LinkageProof(
        master_pubkey=pubkey,
        child_pubkey=child_pubkey,
        attestation=attestation,
        signature=signature,
        purpose=purpose_value,
        index=index,
    )
