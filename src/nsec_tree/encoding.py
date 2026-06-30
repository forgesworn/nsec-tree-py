"""NIP-19 bech32 encoding of Nostr keys (nsec/npub)."""
from __future__ import annotations
import bech32
from .errors import InvalidKey


def _encode(hrp: str, data: bytes) -> str:
    data5 = bech32.convertbits(list(data), 8, 5)
    if data5 is None:
        raise InvalidKey("bech32 convertbits failed")
    out = bech32.bech32_encode(hrp, data5)
    if out is None:
        raise InvalidKey("bech32 encode failed")
    return out


def _decode(expected_hrp: str, s: str) -> bytes:
    hrp, data5 = bech32.bech32_decode(s)
    if hrp != expected_hrp or data5 is None:
        raise InvalidKey(f"expected {expected_hrp}, got {hrp!r}")
    data = bech32.convertbits(data5, 5, 8, False)
    if data is None or len(data) != 32:
        raise InvalidKey("invalid key payload")
    return bytes(data)


def encode_npub(pubkey_xonly: bytes) -> str: return _encode("npub", pubkey_xonly)
def encode_nsec(privkey: bytes) -> str:      return _encode("nsec", privkey)
def decode_npub(npub: str) -> bytes:         return _decode("npub", npub)
def decode_nsec(nsec: str) -> bytes:         return _decode("nsec", nsec)
