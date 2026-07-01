"""Tests for the mnemonic (BIP-39/32) path — PROTOCOL.md §1.1, vectors §6.4-6.6."""
import pytest
from nsec_tree import from_nsec, derive, derive_persona
from nsec_tree.errors import NsecTreeError

mnemonic = pytest.importorskip("mnemonic")  # skip if the [mnemonic] extra is absent
from nsec_tree import from_mnemonic  # noqa: E402

ABANDON = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


def test_vector_6_4_tree_root_and_child():
    root = from_mnemonic(ABANDON)
    assert root.secret.hex() == "cc92d213b5eccd19eb85c12c2cf6fd168f27c2cc347c51a7c4c62ac67795fc65"
    assert root.master_npub == "npub186c5ke7vjsk98z8qx4ctdrggsl2qlu627g6xvg6yumrj5c5c6etqcfaclx"
    child = derive(root, "social", 0)
    assert child.nsec == "nsec17rnusheefhuryyhpprnq5l3zvpzhg24xm9n7588amun6uedvdtyqnpcsm4"


def test_vector_6_5_path_independence():
    mroot = from_mnemonic(ABANDON)
    nsec_root = from_nsec(bytes.fromhex("5f29af3b9676180290e77a4efad265c4c2ff28a5302461f73597fda26bb25731"))
    assert nsec_root.secret.hex() == "3ac534dcff9286225e0a254aade75a991a1f41fcbe719cc7dd899dd833b6e4d6"
    assert mroot.master_pubkey != nsec_root.master_pubkey


def test_vector_6_6_persona_over_mnemonic():
    root = from_mnemonic(ABANDON)
    p = derive_persona(root, "social", 0)
    assert p.identity.npub == "npub1qdztfxg9z46k8qg4707n747y9rt7kl3f954lju2pneesmc3ypf2q83gm0e"


def test_passphrase_changes_root():
    assert from_mnemonic(ABANDON).secret != from_mnemonic(ABANDON, "TREZOR").secret


def test_invalid_mnemonic_rejected():
    with pytest.raises(NsecTreeError):
        from_mnemonic("not a valid bip39 mnemonic at all")


def test_non_string_rejected():
    with pytest.raises(NsecTreeError):
        from_mnemonic(12345)  # type: ignore[arg-type]
