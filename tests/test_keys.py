from nsec_tree.keys import x_only_pubkey

# PROTOCOL.md Vector 1: x_only(tree_root 8d2db9ce…) == master pubkey 8c03e047…
TREE_ROOT = bytes.fromhex("8d2db9ce9548534e7ae924d05e311355e3a12744214c88e65b39fa2bf2df6d6f")
MASTER    = "8c03e047ae60c01e942a8337e71d17e3517fcc63ee6ceff8173bbd23fabe649d"


def test_x_only_matches_vector():
    assert x_only_pubkey(TREE_ROOT).hex() == MASTER
