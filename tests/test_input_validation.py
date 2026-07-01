"""Regression tests for input validation hardening (security review).

All tests here MUST fail (RED) before the corresponding fixes are applied,
then pass (GREEN) after.  They cover:

  I-1   recover() — scan_range + purposes bounds
  M-1   derive() — purpose type, index type
  M-2   derive() — index range
  M-1b  validate_purpose() — non-string purpose
  M-1c  from_nsec() — non-str/bytes nsec
  M-1/M-3  from_event() / _event_fields() — missing keys, non-list tags, huge index
"""
from __future__ import annotations

import pytest

from nsec_tree.root import from_nsec
from nsec_tree.derive import derive
from nsec_tree.recover import recover
from nsec_tree.event import from_event, to_unsigned_event
from nsec_tree.proof import create_full_proof
from nsec_tree.errors import NsecTreeError, InvalidKey, InvalidPurpose, IndexOverflow
from nsec_tree.persona import MAX_SCAN_RANGE, MAX_RECOVERY_PURPOSES

_NSEC_BYTES = bytes.fromhex("01" * 32)
ROOT = from_nsec(_NSEC_BYTES)


# ---------------------------------------------------------------------------
# Fix I-1 — recover() bounds
# ---------------------------------------------------------------------------

def test_recover_scan_range_too_large_raises_invalid_purpose():
    with pytest.raises(InvalidPurpose):
        recover(ROOT, ["x"], MAX_SCAN_RANGE + 1)


def test_recover_scan_range_bool_raises_invalid_purpose():
    with pytest.raises(InvalidPurpose):
        recover(ROOT, ["x"], True)


def test_recover_scan_range_float_raises_invalid_purpose():
    with pytest.raises(InvalidPurpose):
        recover(ROOT, ["x"], 1.5)  # type: ignore[arg-type]


def test_recover_too_many_purposes_raises_invalid_purpose():
    with pytest.raises(InvalidPurpose):
        recover(ROOT, ["x"] * (MAX_RECOVERY_PURPOSES + 1))


def test_recover_purposes_not_list_raises_invalid_purpose():
    with pytest.raises(InvalidPurpose):
        recover(ROOT, "notalist")  # type: ignore[arg-type]


def test_recover_valid_returns_right_shape():
    result = recover(ROOT, ["a"], 2)
    assert isinstance(result, dict)
    assert "a" in result
    assert len(result["a"]) == 2


# ---------------------------------------------------------------------------
# Fix M-2 — derive() index range
# ---------------------------------------------------------------------------

def test_derive_negative_index_raises_index_overflow():
    with pytest.raises(IndexOverflow):
        derive(ROOT, "p", -1)


def test_derive_index_too_large_raises_index_overflow():
    with pytest.raises(IndexOverflow):
        derive(ROOT, "p", 2 ** 32)


# ---------------------------------------------------------------------------
# Fix M-1 — derive() index type
# ---------------------------------------------------------------------------

def test_derive_bool_index_raises_invalid_key():
    with pytest.raises(InvalidKey):
        derive(ROOT, "p", True)  # type: ignore[arg-type]


def test_derive_float_index_raises_invalid_key():
    with pytest.raises(InvalidKey):
        derive(ROOT, "p", 1.5)  # type: ignore[arg-type]


def test_derive_valid_index_zero_works():
    identity = derive(ROOT, "p", 0)
    assert identity.index == 0


def test_derive_valid_index_five_works():
    identity = derive(ROOT, "p", 5)
    assert identity.index == 5


# ---------------------------------------------------------------------------
# Fix M-1b — purpose type check in validate_purpose
# ---------------------------------------------------------------------------

def test_derive_non_string_purpose_raises_invalid_purpose():
    with pytest.raises(InvalidPurpose):
        derive(ROOT, 123)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Fix M-1c — from_nsec type check
# ---------------------------------------------------------------------------

def test_from_nsec_int_raises_invalid_key():
    with pytest.raises(InvalidKey):
        from_nsec(123)  # type: ignore[arg-type]


def test_from_nsec_none_raises_invalid_key():
    with pytest.raises(InvalidKey):
        from_nsec(None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Fix M-1/M-3 — from_event hardening
# ---------------------------------------------------------------------------

def test_from_event_missing_pubkey_raises_nsec_tree_error():
    """A mapping without a 'pubkey' key must raise NsecTreeError, not KeyError."""
    with pytest.raises(NsecTreeError):
        from_event({"tags": [["d", "nsec-tree:" + "aa" * 32]]})


def test_from_event_tags_not_list_raises_nsec_tree_error():
    """A mapping where 'tags' is not a list must raise NsecTreeError, not TypeError."""
    with pytest.raises(NsecTreeError):
        from_event({"pubkey": "aa" * 32, "tags": "notalist"})


def test_from_event_huge_index_raises_nsec_tree_error():
    """An index tag containing 5000 nines must raise NsecTreeError, not ValueError.

    CPython raises ValueError for int(s) when s has more than ~4300 digits.
    We guard length before calling int() so this surfaces as NsecTreeError.
    """
    root = from_nsec(_NSEC_BYTES)
    child = derive(root, "social", 0)
    proof = create_full_proof(root, child)
    ev = to_unsigned_event(proof)

    # Build a mutable copy of the event as a dict and replace the index tag.
    mutated_tags = []
    for tag in ev.tags:
        if tag[0] == "index":
            mutated_tags.append(["index", "9" * 5000])
        else:
            mutated_tags.append(list(tag))

    with pytest.raises(NsecTreeError):
        from_event({"pubkey": ev.pubkey, "tags": mutated_tags})


def test_from_event_non_list_tag_entry_is_skipped():
    """Non-list/tuple entries inside the tags list must be silently skipped.

    The guard in _single_tag_value ensures isinstance(t, (list, tuple)) so a
    stray string or dict inside tags does not cause a TypeError.
    """
    root = from_nsec(_NSEC_BYTES)
    child = derive(root, "social", 0)
    proof = create_full_proof(root, child)
    ev = to_unsigned_event(proof)

    # Inject a rogue non-list entry into the tags list.
    mutated_tags = [list(t) for t in ev.tags]
    mutated_tags.insert(1, "notalist")  # type: ignore[arg-type]

    # Should parse cleanly — the stray string is skipped.
    result = from_event({"pubkey": ev.pubkey, "tags": mutated_tags})
    assert result.purpose == "social"
