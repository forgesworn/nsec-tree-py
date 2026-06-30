"""secp256k1 primitives — BIP-340 x-only pubkeys (coincurve)."""
from __future__ import annotations

from coincurve import PrivateKey

from .errors import InvalidKey


def x_only_pubkey(privkey: bytes) -> bytes:
    """32-byte BIP-340 x-only public key (x-coordinate) for a private key."""
    if len(privkey) != 32:
        raise InvalidKey("private key must be 32 bytes")
    # compressed pubkey is 0x02/0x03 ‖ 32-byte X; x-only is the X coordinate.
    try:
        return PrivateKey(privkey).public_key.format(compressed=True)[1:]
    except ValueError as exc:
        raise InvalidKey("private key is out of range or zero") from exc
