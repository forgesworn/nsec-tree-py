from nsec_tree.root import from_nsec
from nsec_tree.derive import derive
from nsec_tree.recover import recover

ROOT = from_nsec(bytes.fromhex("01" * 32))


def test_recover_reproduces_known_children():
    rec = recover(ROOT, ["social", "commerce"], scan_range=3)
    assert rec["social"][0].private_key == derive(ROOT, "social", 0).private_key
    assert rec["social"][1].private_key == derive(ROOT, "social", 1).private_key
    assert len(rec["commerce"]) == 3
