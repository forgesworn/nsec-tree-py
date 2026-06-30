"""Frozen-vector conformance suite — PROTOCOL.md canonical test vectors.

Asserts the complete nsec → root → child derivation chain through the public
API only.  These vectors are the parity gate between nsec-tree-py and any
other implementation (e.g. nsec-tree-cli).

Differential CLI test is omitted: the skipif guard mis-detected a PATH binary
named ``nsec-tree`` that is not the CLI; the frozen-vector suite below is the
canonical conformance guarantee.
"""

from nsec_tree import derive, from_nsec

# Canonical input: 32 bytes of 0x01.
NSEC = bytes.fromhex("01" * 32)

# Root-level assertions.
EXPECTED_ROOT_SECRET = (
    "8d2db9ce9548534e7ae924d05e311355e3a12744214c88e65b39fa2bf2df6d6f"
)
EXPECTED_MASTER_PUBKEY = (
    "8c03e047ae60c01e942a8337e71d17e3517fcc63ee6ceff8173bbd23fabe649d"
)

# Child vectors: (purpose, index, private_key_hex, public_key_hex, nsec | None, npub | None)
VECTORS = [
    (
        "social",
        0,
        "98e98b476eab3c2bcb5020e4a679a41b74eebfb30a07944c4361c906501265e7",
        "cdc4cd2a01ba1b8afd3299b66c38d13043a19acb687c334f0527cffaf464b372",
        "nsec1nr5ck3mw4v7zhj6syrj2v7dyrd6wa0anpgregnzrv8ysv5qjvhnsafv7mx",
        "npub1ehzv62sphgdc4lfjnxmxcwx3xpp6rxktdp7rxnc9yl8l4arykdeqyfhrxy",
    ),
    (
        "commerce",
        0,
        "fc62a2ec7f91970c485f9d7453268d1a6a07273ee829cf44c87685f78758f04f",
        "8441f7e2a73fea0742ccd12858bd5b95ccae385fbcb2856b7d7177880198a663",
        None,
        None,
    ),
    (
        "social",
        1,
        "802a2fd31d25517bd2bb9b7196c377e6cc2f32728b916c2c3ea71ca703767917",
        "aed0bc4ccccdb868156e38cabf3a6acb98f8fa8a4abe0dcc68851d8468a87cd1",
        None,
        None,
    ),
]


def test_frozen_vectors() -> None:
    """Assert every PROTOCOL.md vector against the public API."""
    root = from_nsec(NSEC)

    assert root.secret.hex() == EXPECTED_ROOT_SECRET, (
        f"root.secret mismatch: {root.secret.hex()}"
    )
    assert root.master_pubkey.hex() == EXPECTED_MASTER_PUBKEY, (
        f"root.master_pubkey mismatch: {root.master_pubkey.hex()}"
    )

    for purpose, index, cpriv, cpub, nsec, npub in VECTORS:
        identity = derive(root, purpose, index)
        assert identity.private_key.hex() == cpriv, (
            f"[{purpose}/{index}] private_key mismatch"
        )
        assert identity.public_key.hex() == cpub, (
            f"[{purpose}/{index}] public_key mismatch"
        )
        if nsec is not None:
            assert identity.nsec == nsec, f"[{purpose}/{index}] nsec mismatch"
        if npub is not None:
            assert identity.npub == npub, f"[{purpose}/{index}] npub mismatch"
