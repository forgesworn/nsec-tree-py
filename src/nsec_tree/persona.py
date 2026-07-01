"""Personas and arbitrary-depth hierarchy — PROTOCOL.md §3.1."""
from __future__ import annotations
from .root import TreeRoot, from_nsec
from .derive import Identity, derive

_PERSONA_PREFIX = "nostr:persona:"


def derive_persona(root: TreeRoot, name: str, index: int = 0) -> Identity:
    return derive(root, _PERSONA_PREFIX + name, index)


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
