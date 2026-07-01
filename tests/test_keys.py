from nsec_tree.keys import x_only_pubkey, schnorr_sign, schnorr_verify

# PROTOCOL.md Vector 1: x_only(tree_root 8d2db9ce…) == master pubkey 8c03e047…
TREE_ROOT = bytes.fromhex("8d2db9ce9548534e7ae924d05e311355e3a12744214c88e65b39fa2bf2df6d6f")
MASTER    = "8c03e047ae60c01e942a8337e71d17e3517fcc63ee6ceff8173bbd23fabe649d"


def test_x_only_matches_vector():
    assert x_only_pubkey(TREE_ROOT).hex() == MASTER


def test_schnorr_sign_verify_roundtrip():
    # Sign a 143-byte message with the vector-1 tree_root secret
    msg = b"x" * 143
    sig = schnorr_sign(TREE_ROOT, msg)
    assert len(sig) == 64
    pubkey = x_only_pubkey(TREE_ROOT)
    assert schnorr_verify(pubkey, sig, msg) is True


def test_schnorr_verify_rejects_tampered_message():
    msg = b"x" * 143
    sig = schnorr_sign(TREE_ROOT, msg)
    tampered = b"y" + msg[1:]
    assert schnorr_verify(x_only_pubkey(TREE_ROOT), sig, tampered) is False


def test_schnorr_sign_is_deterministic():
    msg = b"determinism check" * 8
    sig1 = schnorr_sign(TREE_ROOT, msg)
    sig2 = schnorr_sign(TREE_ROOT, msg)
    assert sig1 == sig2
