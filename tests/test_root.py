"""Tests for root.py — PROTOCOL.md §1.2 vectors."""
from nsec_tree.root import from_nsec, zeroise
from nsec_tree.encoding import encode_nsec
from nsec_tree.derive import derive


def test_from_nsec_bytes_vector_1():
    r = from_nsec(bytes.fromhex("01" * 32))
    assert r.secret.hex()        == "8d2db9ce9548534e7ae924d05e311355e3a12744214c88e65b39fa2bf2df6d6f"
    assert r.master_pubkey.hex() == "8c03e047ae60c01e942a8337e71d17e3517fcc63ee6ceff8173bbd23fabe649d"
    assert r.master_npub == "npub13sp7q3awvrqpa9p2svm7w8ghudghlnrraekwl7qh8w7j8747vjwskvzy2u"


def test_from_nsec_accepts_bech32():
    raw = from_nsec(bytes.fromhex("01" * 32))
    assert from_nsec(encode_nsec(bytes.fromhex("01" * 32))).secret == raw.secret


def test_destroy_overwrites_secret():
    r = from_nsec(bytes.fromhex("01" * 32))
    r.destroy()
    assert r.secret == b"\x00" * 32


def test_zeroise_overwrites_private_key():
    root = from_nsec(bytes.fromhex("01" * 32))
    identity = derive(root, "social", 0)
    zeroise(identity)
    assert identity.private_key == b"\x00" * 32
