"""Tests for persona.py — personas + arbitrary-depth hierarchy."""
import pytest
from nsec_tree import (
    from_nsec, derive, Persona, derive_persona, derive_from_identity,
    derive_from_persona, recover_personas, DEFAULT_PERSONA_NAMES,
    MAX_SCAN_RANGE, MAX_RECOVERY_PURPOSES,
)
from nsec_tree.errors import InvalidPurpose

ROOT = from_nsec(bytes.fromhex("01" * 32))


def test_persona_returns_wrapper():
    p = derive_persona(ROOT, "social")
    assert isinstance(p, Persona)
    assert p.name == "social"
    assert p.index == 0
    # persona "social" == raw purpose "nostr:persona:social" (§3.1)
    assert p.identity.private_key == derive(ROOT, "nostr:persona:social").private_key
    assert p.identity.private_key != derive(ROOT, "social").private_key


def test_persona_name_validation():
    for bad in ["", "   ", "a|b", "a\x00b", "a\x7f"]:
        with pytest.raises(InvalidPurpose):
            derive_persona(ROOT, bad)


def test_default_persona_names():
    assert DEFAULT_PERSONA_NAMES == ("personal", "bitcoiner", "work", "social", "anonymous")


def test_derive_from_persona_two_layer():
    p = derive_persona(ROOT, "work")
    sub = derive_from_persona(p, "payroll")
    assert sub.private_key == derive_from_persona(p, "payroll").private_key
    # two-layer: from_nsec(persona key) then derive — differs from a raw materialise
    assert sub.private_key != derive(ROOT, "payroll").private_key


def test_recover_personas_shape():
    rec = recover_personas(ROOT, ["work", "social"], scan_range=3)
    assert set(rec) == {"work", "social"}
    assert [p.index for p in rec["work"]] == [0, 1, 2]
    assert all(isinstance(p, Persona) for p in rec["work"])


def test_recover_personas_defaults():
    rec = recover_personas(ROOT)
    assert set(rec) == set(DEFAULT_PERSONA_NAMES)
    assert all(len(v) == 1 for v in rec.values())


def test_recover_personas_bounds():
    with pytest.raises(InvalidPurpose):
        recover_personas(ROOT, ["a"], scan_range=0)
    with pytest.raises(InvalidPurpose):
        recover_personas(ROOT, ["a"], scan_range=MAX_SCAN_RANGE + 1)
    with pytest.raises(InvalidPurpose):
        recover_personas(ROOT, ["a"] * (MAX_RECOVERY_PURPOSES + 1))


def test_derive_from_identity_unchanged_matches_ts():
    # regression: hierarchy still matches the TS reference (frozen vector)
    social = derive(ROOT, "social", 0)
    sub = derive_from_identity(social, "commerce", 0)
    assert sub.npub == "npub1tjetxpsqdreul7xllhfz6x2leelp9p65t7364n8n5xcdw3eqrw0qad9gwz"
