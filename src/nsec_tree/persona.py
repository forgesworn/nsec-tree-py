"""Personas and arbitrary-depth hierarchy — PROTOCOL.md §3.1."""
from __future__ import annotations
import re
from dataclasses import dataclass

from .root import TreeRoot, from_nsec
from .derive import Identity, derive
from .errors import InvalidPurpose

_PERSONA_PREFIX = "nostr:persona:"
_PERSONA_UNSAFE = re.compile(r"[\x00-\x1f\x7f|]")

# Constants mirrored from the TS reference (types.ts).
MAX_INDEX = 0xFFFFFFFF
DEFAULT_SCAN_RANGE = 20
MAX_SCAN_RANGE = 10_000
MAX_RECOVERY_PURPOSES = 1_000

DEFAULT_PERSONA_NAMES: tuple[str, ...] = (
    "personal", "bitcoiner", "work", "social", "anonymous",
)


@dataclass(frozen=True)
class Persona:
    identity: Identity
    name: str
    index: int


def validate_persona_name(name: str) -> None:
    if not isinstance(name, str):
        raise InvalidPurpose("persona name must be a string")
    if len(name) == 0:
        raise InvalidPurpose("persona name must not be empty")
    if name.strip() == "":
        raise InvalidPurpose("persona name must not be whitespace-only")
    if _PERSONA_UNSAFE.search(name):
        raise InvalidPurpose('persona name must not contain "|" or control characters')


def derive_persona(root: TreeRoot, name: str, index: int = 0) -> Persona:
    validate_persona_name(name)
    identity = derive(root, _PERSONA_PREFIX + name, index)
    return Persona(identity, name, identity.index)


def derive_from_identity(identity: Identity, purpose: str, index: int = 0) -> Identity:
    """Derive a child from an existing identity (arbitrary-depth hierarchy).

    The parent private key is first run through ``from_nsec`` (the
    ``nsec-tree-root`` HMAC) to form a transient tree root, then the child is
    derived from that — matching the TypeScript reference and preserving the
    signing-key/derivation-key separation of PROTOCOL.md §1.2. The transient
    root is destroyed afterwards.
    """
    intermediate = from_nsec(identity.private_key)
    try:
        return derive(intermediate, purpose, index)
    finally:
        intermediate.destroy()


def derive_from_persona(persona: Persona, purpose: str, index: int = 0) -> Identity:
    """Derive a sub-identity within a persona (two-level hierarchy)."""
    intermediate = from_nsec(persona.identity.private_key)
    try:
        return derive(intermediate, purpose, index)
    finally:
        intermediate.destroy()


def recover_personas(
    root: TreeRoot,
    names: tuple[str, ...] | list[str] = DEFAULT_PERSONA_NAMES,
    scan_range: int = 1,
) -> dict[str, list[Persona]]:
    if not isinstance(names, (list, tuple)):
        raise InvalidPurpose("names must be a list of strings")
    if len(names) > MAX_RECOVERY_PURPOSES:
        raise InvalidPurpose(f"names exceeds maximum ({MAX_RECOVERY_PURPOSES})")
    if (
        not isinstance(scan_range, int)
        or isinstance(scan_range, bool)
        or scan_range < 1
        or scan_range > MAX_SCAN_RANGE
    ):
        raise InvalidPurpose(f"scan_range must be an integer in [1, {MAX_SCAN_RANGE}]")
    return {
        name: [derive_persona(root, name, i) for i in range(scan_range)]
        for name in names
    }
