"""Tests for derive.py — PROTOCOL.md §2 + §4 vectors."""
from nsec_tree.root import from_nsec
from nsec_tree.derive import derive

ROOT = from_nsec(bytes.fromhex("01" * 32))


def test_vector_1_social_0():
    i = derive(ROOT, "social", 0)
    assert i.private_key.hex() == "98e98b476eab3c2bcb5020e4a679a41b74eebfb30a07944c4361c906501265e7"
    assert i.public_key.hex()  == "cdc4cd2a01ba1b8afd3299b66c38d13043a19acb687c334f0527cffaf464b372"
    assert i.nsec == "nsec1nr5ck3mw4v7zhj6syrj2v7dyrd6wa0anpgregnzrv8ysv5qjvhnsafv7mx"
    assert i.npub == "npub1ehzv62sphgdc4lfjnxmxcwx3xpp6rxktdp7rxnc9yl8l4arykdeqyfhrxy"
    assert i.index == 0


def test_vector_2_commerce_0():
    i = derive(ROOT, "commerce", 0)
    assert i.private_key.hex() == "fc62a2ec7f91970c485f9d7453268d1a6a07273ee829cf44c87685f78758f04f"
    assert i.public_key.hex()  == "8441f7e2a73fea0742ccd12858bd5b95ccae385fbcb2856b7d7177880198a663"


def test_vector_3_social_1():
    i = derive(ROOT, "social", 1)
    assert i.private_key.hex() == "802a2fd31d25517bd2bb9b7196c377e6cc2f32728b916c2c3ea71ca703767917"
    assert i.public_key.hex()  == "aed0bc4ccccdb868156e38cabf3a6acb98f8fa8a4abe0dcc68851d8468a87cd1"
    assert i.index == 1
