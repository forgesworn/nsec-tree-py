"""Tests for NIP-78 (Kind 30078) event conversion — mirrors the TS event.test.ts.

Includes a frozen cross-impl interop lock: the tag arrays below are the genuine
output of the TypeScript `toUnsignedEvent` for the frozen @noble proofs, so the
Python port is byte-locked to real TS output (created_at omitted — clock-dependent).
"""
from __future__ import annotations

import pytest

from nsec_tree import (
    NSEC_TREE_D_PREFIX,
    NSEC_TREE_EVENT_KIND,
    UnsignedEvent,
    derive,
    from_event,
    from_nsec,
    to_unsigned_event,
)
from nsec_tree.errors import NsecTreeError
from nsec_tree.proof import (
    create_blind_proof,
    create_full_proof,
    proof_from_dict,
    verify_proof,
    LinkageProof,
)

_NSEC_BYTES = bytes.fromhex("01" * 32)


def _root():
    return from_nsec(_NSEC_BYTES)


def _child(root):
    return derive(root, "social", 0)


def _tag(tags, name):
    for t in tags:
        if t[0] == name:
            return t
    return None


def _full_event_dict():
    """A fresh, valid full-proof event as a mutable {pubkey, tags} dict."""
    root = _root()
    proof = create_full_proof(root, _child(root))
    ev = to_unsigned_event(proof)
    return {"pubkey": ev.pubkey, "tags": [list(t) for t in ev.tags]}


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

def test_kind_constant():
    assert NSEC_TREE_EVENT_KIND == 30078


def test_d_prefix_constant():
    assert NSEC_TREE_D_PREFIX == "nsec-tree:"


# ---------------------------------------------------------------------------
# to_unsigned_event
# ---------------------------------------------------------------------------

def test_full_proof_to_event():
    root = _root()
    proof = create_full_proof(root, _child(root))
    ev = to_unsigned_event(proof, created_at=1_700_000_000)

    assert ev.kind == NSEC_TREE_EVENT_KIND
    assert ev.pubkey == proof.master_pubkey
    assert ev.content == ""
    assert ev.created_at == 1_700_000_000
    assert _tag(ev.tags, "d") == ["d", f"{NSEC_TREE_D_PREFIX}{proof.child_pubkey}"]
    assert _tag(ev.tags, "p") == ["p", proof.child_pubkey]
    assert _tag(ev.tags, "purpose") == ["purpose", "social"]
    assert _tag(ev.tags, "index") == ["index", "0"]
    assert _tag(ev.tags, "attestation") == ["attestation", proof.attestation]
    assert _tag(ev.tags, "proof-sig") == ["proof-sig", proof.signature]


def test_blind_proof_to_event_omits_purpose_index():
    root = _root()
    proof = create_blind_proof(root, _child(root))
    ev = to_unsigned_event(proof)

    assert _tag(ev.tags, "purpose") is None
    assert _tag(ev.tags, "index") is None
    assert len(ev.tags) == 4  # d, p, attestation, proof-sig


def test_default_created_at_is_current_int():
    root = _root()
    proof = create_blind_proof(root, _child(root))
    ev = to_unsigned_event(proof)
    assert isinstance(ev.created_at, int)
    assert ev.created_at > 1_600_000_000


def test_returns_unsigned_event_dataclass():
    root = _root()
    proof = create_blind_proof(root, _child(root))
    ev = to_unsigned_event(proof)
    assert isinstance(ev, UnsignedEvent)


# ---------------------------------------------------------------------------
# to_unsigned_event — structural validation
# ---------------------------------------------------------------------------

def test_to_event_accepts_well_formed():
    root = _root()
    proof = create_full_proof(root, _child(root))
    to_unsigned_event(proof)  # must not raise


def test_to_event_rejects_non_canonical_attestation():
    root = _root()
    proof = create_full_proof(root, _child(root))
    tampered = LinkageProof(
        master_pubkey=proof.master_pubkey,
        child_pubkey=proof.child_pubkey,
        attestation=proof.attestation + "x",
        signature=proof.signature,
        purpose=proof.purpose,
        index=proof.index,
    )
    with pytest.raises(NsecTreeError, match="canonical form"):
        to_unsigned_event(tampered)


def test_to_event_rejects_purpose_without_index():
    root = _root()
    proof = create_blind_proof(root, _child(root))
    bogus = LinkageProof(
        master_pubkey=proof.master_pubkey,
        child_pubkey=proof.child_pubkey,
        attestation=proof.attestation,
        signature=proof.signature,
        purpose="social",
        index=None,
    )
    with pytest.raises(NsecTreeError, match="malformed"):
        to_unsigned_event(bogus)


def test_to_event_rejects_bad_master_pubkey():
    root = _root()
    proof = create_blind_proof(root, _child(root))
    bogus = LinkageProof(
        master_pubkey="zz" * 32,
        child_pubkey=proof.child_pubkey,
        attestation=proof.attestation,
        signature=proof.signature,
    )
    with pytest.raises(NsecTreeError, match="malformed"):
        to_unsigned_event(bogus)


def test_to_event_rejects_uppercase_child_pubkey():
    root = _root()
    proof = create_blind_proof(root, _child(root))
    bogus = LinkageProof(
        master_pubkey=proof.master_pubkey,
        child_pubkey=proof.child_pubkey.upper(),
        attestation=proof.attestation,
        signature=proof.signature,
    )
    with pytest.raises(NsecTreeError, match="malformed"):
        to_unsigned_event(bogus)


# ---------------------------------------------------------------------------
# from_event — round-trip
# ---------------------------------------------------------------------------

def test_full_proof_roundtrip_via_event():
    root = _root()
    proof = create_full_proof(root, _child(root))
    ev = to_unsigned_event(proof)
    restored = from_event(ev)  # accepts the UnsignedEvent dataclass directly
    assert verify_proof(restored) is True


def test_blind_proof_roundtrip_via_event():
    root = _root()
    proof = create_blind_proof(root, _child(root))
    ev = to_unsigned_event(proof)
    restored = from_event(ev)
    assert verify_proof(restored) is True
    assert restored.purpose is None
    assert restored.index is None


def test_from_event_accepts_plain_dict():
    restored = from_event(_full_event_dict())
    assert verify_proof(restored) is True


# ---------------------------------------------------------------------------
# from_event — validation
# ---------------------------------------------------------------------------

def test_from_event_missing_d_tag():
    with pytest.raises(NsecTreeError):
        from_event({"pubkey": "aa" * 32, "tags": [["p", "bb" * 32]]})


def test_from_event_wrong_d_prefix():
    with pytest.raises(NsecTreeError):
        from_event({"pubkey": "aa" * 32, "tags": [["d", "wrong:prefix"]]})


def test_from_event_missing_attestation():
    ev = _full_event_dict()
    ev["tags"] = [t for t in ev["tags"] if t[0] != "attestation"]
    with pytest.raises(NsecTreeError):
        from_event(ev)


def test_from_event_missing_proof_sig():
    ev = _full_event_dict()
    ev["tags"] = [t for t in ev["tags"] if t[0] != "proof-sig"]
    with pytest.raises(NsecTreeError):
        from_event(ev)


def test_from_event_non_numeric_index():
    ev = _full_event_dict()
    _tag(ev["tags"], "index")[1] = "not-a-number"
    with pytest.raises(NsecTreeError):
        from_event(ev)


def test_from_event_negative_index():
    ev = _full_event_dict()
    _tag(ev["tags"], "index")[1] = "-1"
    with pytest.raises(NsecTreeError):
        from_event(ev)


def test_from_event_purpose_without_index():
    ev = _full_event_dict()
    ev["tags"] = [t for t in ev["tags"] if t[0] != "index"]
    with pytest.raises(NsecTreeError):
        from_event(ev)


def test_from_event_index_without_purpose():
    ev = _full_event_dict()
    ev["tags"] = [t for t in ev["tags"] if t[0] != "purpose"]
    with pytest.raises(NsecTreeError):
        from_event(ev)


def test_from_event_index_exceeds_uint32_max():
    ev = _full_event_dict()
    _tag(ev["tags"], "index")[1] = "4294967296"
    with pytest.raises(NsecTreeError, match="exceeds maximum"):
        from_event(ev)


def test_from_event_index_trailing_chars():
    ev = _full_event_dict()
    _tag(ev["tags"], "index")[1] = "42abc"
    with pytest.raises(NsecTreeError):
        from_event(ev)


def test_from_event_index_leading_zeros():
    ev = _full_event_dict()
    _tag(ev["tags"], "index")[1] = "007"
    with pytest.raises(NsecTreeError):
        from_event(ev)


def test_from_event_index_hex_prefix():
    ev = _full_event_dict()
    _tag(ev["tags"], "index")[1] = "0x1F"
    with pytest.raises(NsecTreeError):
        from_event(ev)


def test_from_event_index_decimal_point():
    ev = _full_event_dict()
    _tag(ev["tags"], "index")[1] = "3.14"
    with pytest.raises(NsecTreeError):
        from_event(ev)


def test_from_event_non_hex_child_pubkey():
    ev = _full_event_dict()
    _tag(ev["tags"], "d")[1] = "nsec-tree:not-valid-hex"
    with pytest.raises(NsecTreeError, match="childPubkey"):
        from_event(ev)


def test_from_event_uppercase_child_pubkey():
    ev = _full_event_dict()
    _tag(ev["tags"], "d")[1] = "nsec-tree:" + "AA" * 32
    with pytest.raises(NsecTreeError, match="childPubkey"):
        from_event(ev)


def test_from_event_missing_p_tag():
    ev = _full_event_dict()
    ev["tags"] = [t for t in ev["tags"] if t[0] != "p"]
    with pytest.raises(NsecTreeError):
        from_event(ev)


def test_from_event_p_mismatch():
    ev = _full_event_dict()
    _tag(ev["tags"], "p")[1] = "bb" * 32
    with pytest.raises(NsecTreeError, match="p tag"):
        from_event(ev)


def test_from_event_non_hex_pubkey():
    ev = _full_event_dict()
    ev["pubkey"] = "not-hex"
    with pytest.raises(NsecTreeError, match="pubkey"):
        from_event(ev)


def test_from_event_non_hex_proof_sig():
    ev = _full_event_dict()
    _tag(ev["tags"], "proof-sig")[1] = "ZZ" * 64
    with pytest.raises(NsecTreeError, match="proof-sig"):
        from_event(ev)


def test_from_event_short_proof_sig():
    ev = _full_event_dict()
    _tag(ev["tags"], "proof-sig")[1] = "aa" * 32
    with pytest.raises(NsecTreeError, match="proof-sig"):
        from_event(ev)


# ---------------------------------------------------------------------------
# from_event — duplicate tag rejection (security fix)
# ---------------------------------------------------------------------------

def test_from_event_duplicate_attestation():
    ev = _full_event_dict()
    ev["tags"].append(["attestation", "nsec-tree:link|aa|bb|forged|0"])
    with pytest.raises(NsecTreeError, match='Duplicate "attestation"'):
        from_event(ev)


def test_from_event_duplicate_proof_sig():
    ev = _full_event_dict()
    ev["tags"].append(["proof-sig", "00" * 64])
    with pytest.raises(NsecTreeError, match='Duplicate "proof-sig"'):
        from_event(ev)


def test_from_event_duplicate_d():
    ev = _full_event_dict()
    ev["tags"].append(["d", "nsec-tree:" + "cc" * 32])
    with pytest.raises(NsecTreeError, match='Duplicate "d"'):
        from_event(ev)


def test_from_event_duplicate_p():
    ev = _full_event_dict()
    ev["tags"].append(["p", "dd" * 32])
    with pytest.raises(NsecTreeError, match='Duplicate "p"'):
        from_event(ev)


def test_from_event_duplicate_purpose():
    ev = _full_event_dict()
    ev["tags"].append(["purpose", "forged"])
    with pytest.raises(NsecTreeError, match='Duplicate "purpose"'):
        from_event(ev)


def test_from_event_duplicate_index():
    ev = _full_event_dict()
    ev["tags"].append(["index", "999"])
    with pytest.raises(NsecTreeError, match='Duplicate "index"'):
        from_event(ev)


# ---------------------------------------------------------------------------
# Trailing-newline strictness — Python's `$` matches before a trailing "\n" but
# JavaScript's `$` does not; the port anchors with `\Z` so it rejects exactly
# what the TS reference rejects. (Cross-impl parity regression.)
# ---------------------------------------------------------------------------

def test_from_event_rejects_index_trailing_newline():
    ev = _full_event_dict()
    _tag(ev["tags"], "index")[1] = "0\n"
    with pytest.raises(NsecTreeError):
        from_event(ev)


def test_from_event_rejects_proof_sig_trailing_newline():
    ev = _full_event_dict()
    _tag(ev["tags"], "proof-sig")[1] = _tag(ev["tags"], "proof-sig")[1] + "\n"
    with pytest.raises(NsecTreeError, match="proof-sig"):
        from_event(ev)


def test_from_event_rejects_pubkey_trailing_newline():
    ev = _full_event_dict()
    ev["pubkey"] = ev["pubkey"] + "\n"
    with pytest.raises(NsecTreeError, match="pubkey"):
        from_event(ev)


def test_from_event_rejects_child_pubkey_trailing_newline():
    # d and p tags both carry the trailing newline so the p==child check passes,
    # forcing the failure onto the childPubkey hex validation.
    ev = _full_event_dict()
    child = _tag(ev["tags"], "p")[1]
    _tag(ev["tags"], "d")[1] = "nsec-tree:" + child + "\n"
    _tag(ev["tags"], "p")[1] = child + "\n"
    with pytest.raises(NsecTreeError, match="childPubkey"):
        from_event(ev)


# ---------------------------------------------------------------------------
# FROZEN cross-impl interop lock — genuine TypeScript toUnsignedEvent output.
# These MUST match / verify in Python — permanent cross-impl conformance gate.
# ---------------------------------------------------------------------------

TS_MASTER = "8c03e047ae60c01e942a8337e71d17e3517fcc63ee6ceff8173bbd23fabe649d"

TS_FULL = {
    "masterPubkey": TS_MASTER,
    "childPubkey": "cdc4cd2a01ba1b8afd3299b66c38d13043a19acb687c334f0527cffaf464b372",
    "purpose": "social",
    "index": 0,
    "attestation": "nsec-tree:link|8c03e047ae60c01e942a8337e71d17e3517fcc63ee6ceff8173bbd23fabe649d|cdc4cd2a01ba1b8afd3299b66c38d13043a19acb687c334f0527cffaf464b372|social|0",
    "signature": "a2f7797cef1d0ae98a9ffd45e06b5e0e14c7ad3b868827b092b750c00f73f5ddc64636701a8c00f6366bd0dd254788051efa75a68001ac14e214012ae058b89d",
}

TS_BLIND = {
    "masterPubkey": TS_MASTER,
    "childPubkey": "cdc4cd2a01ba1b8afd3299b66c38d13043a19acb687c334f0527cffaf464b372",
    "attestation": "nsec-tree:own|8c03e047ae60c01e942a8337e71d17e3517fcc63ee6ceff8173bbd23fabe649d|cdc4cd2a01ba1b8afd3299b66c38d13043a19acb687c334f0527cffaf464b372",
    "signature": "a2d5478ee7fa453a3972e837982434639bf045ffa53b17d3be055cd5a471c500b875bbbb90cc03335492e62ff4af6e97e78dbd752efde7842b3cde18e05b52f8",
}

# Genuine TS `toUnsignedEvent(...).tags` for the proofs above (created_at omitted).
TS_EVENT_FULL_TAGS = [
    ["d", "nsec-tree:cdc4cd2a01ba1b8afd3299b66c38d13043a19acb687c334f0527cffaf464b372"],
    ["p", "cdc4cd2a01ba1b8afd3299b66c38d13043a19acb687c334f0527cffaf464b372"],
    ["purpose", "social"],
    ["index", "0"],
    ["attestation", "nsec-tree:link|8c03e047ae60c01e942a8337e71d17e3517fcc63ee6ceff8173bbd23fabe649d|cdc4cd2a01ba1b8afd3299b66c38d13043a19acb687c334f0527cffaf464b372|social|0"],
    ["proof-sig", "a2f7797cef1d0ae98a9ffd45e06b5e0e14c7ad3b868827b092b750c00f73f5ddc64636701a8c00f6366bd0dd254788051efa75a68001ac14e214012ae058b89d"],
]

TS_EVENT_BLIND_TAGS = [
    ["d", "nsec-tree:cdc4cd2a01ba1b8afd3299b66c38d13043a19acb687c334f0527cffaf464b372"],
    ["p", "cdc4cd2a01ba1b8afd3299b66c38d13043a19acb687c334f0527cffaf464b372"],
    ["attestation", "nsec-tree:own|8c03e047ae60c01e942a8337e71d17e3517fcc63ee6ceff8173bbd23fabe649d|cdc4cd2a01ba1b8afd3299b66c38d13043a19acb687c334f0527cffaf464b372"],
    ["proof-sig", "a2d5478ee7fa453a3972e837982434639bf045ffa53b17d3be055cd5a471c500b875bbbb90cc03335492e62ff4af6e97e78dbd752efde7842b3cde18e05b52f8"],
]


def test_python_to_event_matches_ts_full():
    ev = to_unsigned_event(proof_from_dict(TS_FULL), created_at=0)
    assert ev.kind == 30078
    assert ev.pubkey == TS_MASTER
    assert ev.content == ""
    assert ev.tags == TS_EVENT_FULL_TAGS


def test_python_to_event_matches_ts_blind():
    ev = to_unsigned_event(proof_from_dict(TS_BLIND), created_at=0)
    assert ev.tags == TS_EVENT_BLIND_TAGS


def test_python_from_ts_full_event_verifies():
    proof = from_event({"pubkey": TS_MASTER, "tags": TS_EVENT_FULL_TAGS})
    assert verify_proof(proof) is True
    assert proof.purpose == "social"
    assert proof.index == 0


def test_python_from_ts_blind_event_verifies():
    proof = from_event({"pubkey": TS_MASTER, "tags": TS_EVENT_BLIND_TAGS})
    assert verify_proof(proof) is True
    assert proof.purpose is None
    assert proof.index is None
