"""Tests for NIP-19 bech32 encoding."""
from nsec_tree.encoding import encode_npub, encode_nsec, decode_npub, decode_nsec

CPRIV = bytes.fromhex("98e98b476eab3c2bcb5020e4a679a41b74eebfb30a07944c4361c906501265e7")
CPUB  = bytes.fromhex("cdc4cd2a01ba1b8afd3299b66c38d13043a19acb687c334f0527cffaf464b372")
NSEC  = "nsec1nr5ck3mw4v7zhj6syrj2v7dyrd6wa0anpgregnzrv8ysv5qjvhnsafv7mx"
NPUB  = "npub1ehzv62sphgdc4lfjnxmxcwx3xpp6rxktdp7rxnc9yl8l4arykdeqyfhrxy"


def test_encode_matches_vector():
    assert encode_nsec(CPRIV) == NSEC
    assert encode_npub(CPUB) == NPUB


def test_decode_roundtrip():
    assert decode_nsec(NSEC) == CPRIV
    assert decode_npub(NPUB) == CPUB
