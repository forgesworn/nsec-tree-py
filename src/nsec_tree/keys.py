"""secp256k1 primitives — BIP-340 x-only pubkeys and Schnorr signing (coincurve)."""
from __future__ import annotations

from coincurve import PrivateKey, PublicKeyXOnly
from coincurve._libsecp256k1 import ffi, lib
from coincurve.context import GLOBAL_CONTEXT

from .errors import InvalidKey, NsecTreeError


def x_only_pubkey(privkey: bytes) -> bytes:
    """32-byte BIP-340 x-only public key (x-coordinate) for a private key."""
    if len(privkey) != 32:
        raise InvalidKey("private key must be 32 bytes")
    # compressed pubkey is 0x02/0x03 ‖ 32-byte X; x-only is the X coordinate.
    try:
        return PrivateKey(privkey).public_key.format(compressed=True)[1:]
    except ValueError as exc:
        raise InvalidKey("private key is out of range or zero") from exc


def schnorr_sign(secret: bytes, message: bytes) -> bytes:
    """BIP-340 Schnorr signature over a variable-length message.

    Uses libsecp256k1's ``schnorrsig_sign_custom`` (deterministic, zero
    auxiliary randomness) so signatures are reproducible and interoperable
    with any BIP-340 verifier (e.g. @noble/curves).
    """
    if len(secret) != 32:
        raise InvalidKey("secret key must be 32 bytes")
    ctx = GLOBAL_CONTEXT.ctx
    keypair = ffi.new("secp256k1_keypair *")
    if lib.secp256k1_keypair_create(ctx, keypair, secret) != 1:
        raise InvalidKey("invalid secret key")
    sig = ffi.new("unsigned char[64]")
    if lib.secp256k1_schnorrsig_sign_custom(ctx, sig, message, len(message), keypair, ffi.NULL) != 1:
        raise NsecTreeError("schnorr signing failed")
    return bytes(ffi.buffer(sig, 64))


def schnorr_verify(pubkey_xonly: bytes, signature: bytes, message: bytes) -> bool:
    """Verify a BIP-340 Schnorr signature (variable-length message)."""
    return PublicKeyXOnly(pubkey_xonly).verify(signature, message)
