"""Tree root from an nsec — PROTOCOL.md §1.2."""
from __future__ import annotations
import hmac
import hashlib
from dataclasses import dataclass

from .keys import x_only_pubkey
from .encoding import encode_npub, decode_nsec
from .derive import Identity
from .errors import InvalidKey

_ROOT_LABEL = b"nsec-tree-root"


@dataclass
class TreeRoot:
    secret: bytes
    master_pubkey: bytes
    master_npub: str

    def destroy(self) -> None:
        self.secret = b"\x00" * len(self.secret)


def _create_tree_root(secret: bytes) -> TreeRoot:
    """Wrap a 32-byte root secret as a TreeRoot (computes master pubkey/npub).

    No HMAC here — the caller supplies the final tree-root secret. `from_nsec`
    HMACs first; `from_mnemonic` derives via BIP-32 and passes the key directly.
    """
    master = x_only_pubkey(secret)
    return TreeRoot(secret, master, encode_npub(master))


def from_nsec(nsec: str | bytes) -> TreeRoot:
    if not isinstance(nsec, (str, bytes, bytearray)):
        raise InvalidKey("nsec must be a str, bytes, or bytearray")
    if isinstance(nsec, str):
        nsec_bytes = decode_nsec(nsec)
    else:
        nsec_bytes = bytes(nsec)
    if len(nsec_bytes) != 32:
        raise InvalidKey("nsec must decode to 32 bytes")
    secret = hmac.new(nsec_bytes, _ROOT_LABEL, hashlib.sha256).digest()
    return _create_tree_root(secret)


def zeroise(identity: Identity) -> None:
    object.__setattr__(identity, "private_key", b"\x00" * len(identity.private_key))
    object.__setattr__(identity, "nsec", "")
