"""Tests for persona.py — personas + arbitrary-depth hierarchy."""
from nsec_tree.root import from_nsec
from nsec_tree.derive import derive
from nsec_tree.persona import derive_persona, derive_from_identity

ROOT = from_nsec(bytes.fromhex("01" * 32))


def test_persona_is_namespaced_child():
    # persona "social" == raw purpose "nostr:persona:social" (§3.1), and != raw "social"
    assert derive_persona(ROOT, "social").private_key == derive(ROOT, "nostr:persona:social").private_key
    assert derive_persona(ROOT, "social").private_key != derive(ROOT, "social").private_key


def test_subtree_uses_child_secret():
    child = derive(ROOT, "work")
    sub = derive_from_identity(child, "payroll")
    # deterministic + distinct from a root-level derive of the same purpose
    assert sub.private_key == derive_from_identity(child, "payroll").private_key
    assert sub.private_key != derive(ROOT, "payroll").private_key


def test_derive_from_identity_matches_ts_reference():
    """Hierarchy must match the TypeScript reference byte-for-byte.

    `derive_from_identity` runs the parent key through `from_nsec` (the
    `nsec-tree-root` HMAC) before deriving — the same two-layer step as TS
    `deriveFromIdentity`. Frozen from genuine TS output for
    from_nsec(0x01*32) -> derive("social") -> derive_from_identity("commerce").
    """
    social = derive(ROOT, "social", 0)
    sub = derive_from_identity(social, "commerce", 0)
    assert sub.npub == "npub1tjetxpsqdreul7xllhfz6x2leelp9p65t7364n8n5xcdw3eqrw0qad9gwz"
    assert sub.nsec == "nsec1ll3y9vpc7cm5kfvefzzqge2z6zg4vthxa4qr206wuuy6jvs74lzsq9agkg"
    assert sub.public_key.hex() == "5cb2b3060068f3cff8dffdd22d195fce7e1287545fa3aaccf3a1b0d747201b9e"
