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
