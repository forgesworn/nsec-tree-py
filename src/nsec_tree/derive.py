"""Child key derivation — PROTOCOL.md §2 (HMAC message) + §4 (curve-order retry)."""
from __future__ import annotations
import hmac
import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .keys import x_only_pubkey
from .encoding import encode_nsec, encode_npub
from .validate import validate_purpose
from .errors import IndexOverflow

if TYPE_CHECKING:
    from .root import TreeRoot

_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_DOMAIN = b"nsec-tree"


@dataclass(frozen=True)
class Identity:
    private_key: bytes
    public_key: bytes
    nsec: str
    npub: str
    purpose: str
    index: int


def _derive_from_secret(tree_root_secret: bytes, purpose: str, index: int) -> tuple[bytes, int]:
    i = index
    while i <= 0xFFFFFFFF:
        msg = _DOMAIN + b"\x00" + purpose.encode("utf-8") + b"\x00" + i.to_bytes(4, "big")
        candidate = hmac.new(tree_root_secret, msg, hashlib.sha256).digest()
        if 0 < int.from_bytes(candidate, "big") < _N:
            return candidate, i
        i += 1
    raise IndexOverflow("index exceeded 2^32-1")


def _materialise(secret_key: bytes, purpose: str, index: int) -> Identity:
    """Build an Identity from a tree-root secret or parent private key."""
    priv, actual = _derive_from_secret(secret_key, purpose, index)
    pub = x_only_pubkey(priv)
    return Identity(priv, pub, encode_nsec(priv), encode_npub(pub), purpose, actual)


def derive(root: "TreeRoot", purpose: str, index: int = 0) -> Identity:
    validate_purpose(purpose)
    return _materialise(root.secret, purpose, index)
