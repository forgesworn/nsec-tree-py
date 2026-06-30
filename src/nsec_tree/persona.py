"""Personas and arbitrary-depth hierarchy — PROTOCOL.md §3.1."""
from __future__ import annotations
from .root import TreeRoot
from .derive import Identity, derive, _derive_from_secret
from .keys import x_only_pubkey
from .encoding import encode_nsec, encode_npub
from .validate import validate_purpose

_PERSONA_PREFIX = "nostr:persona:"


def derive_persona(root: TreeRoot, name: str, index: int = 0) -> Identity:
    return derive(root, _PERSONA_PREFIX + name, index)


def derive_from_identity(identity: Identity, purpose: str, index: int = 0) -> Identity:
    validate_purpose(purpose)
    priv, actual = _derive_from_secret(identity.private_key, purpose, index)
    pub = x_only_pubkey(priv)
    return Identity(priv, pub, encode_nsec(priv), encode_npub(pub), purpose, actual)
