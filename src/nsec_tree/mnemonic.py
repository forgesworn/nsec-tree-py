"""Mnemonic (BIP-39 / BIP-32) tree root — PROTOCOL.md §1.1.

Requires the optional extra: ``pip install nsec-tree[mnemonic]``.
"""
from __future__ import annotations

from .errors import NsecTreeError
from .root import TreeRoot, _create_tree_root

_DERIVATION_PATH = "m/44'/1237'/727'/0'/0'"


def from_mnemonic(mnemonic: str, passphrase: str | None = None) -> TreeRoot:
    """Build a tree root from a BIP-39 mnemonic.

    Derives the BIP-32 key at ``m/44'/1237'/727'/0'/0'`` (all hardened); that key
    is the tree-root secret (no extra HMAC — distinct from ``from_nsec``).
    Zeroisation of intermediate material is best-effort (CPython cannot scrub
    immutable ``bytes`` in place). Raises ``NsecTreeError`` if the ``[mnemonic]``
    extra is not installed or the mnemonic is invalid.
    """
    if not isinstance(mnemonic, str):
        raise NsecTreeError("mnemonic must be a string")
    if passphrase is not None and not isinstance(passphrase, str):
        raise NsecTreeError("passphrase must be a string")

    try:
        from bip32 import BIP32
        from mnemonic import Mnemonic
    except ImportError as exc:
        raise NsecTreeError(
            "mnemonic support requires the optional extra: "
            "pip install nsec-tree[mnemonic]"
        ) from exc

    mnemo = Mnemonic("english")
    if not mnemo.check(mnemonic):
        raise NsecTreeError("Invalid BIP-39 mnemonic")

    seed = mnemo.to_seed(mnemonic, passphrase or "")
    secret = BIP32.from_seed(seed).get_privkey_from_path(_DERIVATION_PATH)
    return _create_tree_root(secret)
