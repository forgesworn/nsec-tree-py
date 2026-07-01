"""Tests for linkage proofs — PROTOCOL.md §5."""
from __future__ import annotations

import pytest

from nsec_tree import from_nsec, derive
from nsec_tree.errors import InvalidPurpose
from nsec_tree.proof import (
    LinkageProof,
    canonical_attestation,
    create_blind_proof,
    create_full_proof,
    verify_proof,
    proof_to_dict,
    proof_from_dict,
)

# Standard test vectors: nsec_bytes = 0x01 * 32
_NSEC_BYTES = bytes.fromhex("01" * 32)


def _root():
    return from_nsec(_NSEC_BYTES)


def _child(root=None):
    if root is None:
        root = _root()
    return derive(root, "social", 0)


# ---------------------------------------------------------------------------
# Roundtrip — blind proof
# ---------------------------------------------------------------------------

def test_blind_proof_roundtrip():
    root = _root()
    child = _child(root)
    proof = create_blind_proof(root, child)
    assert verify_proof(proof) is True


def test_blind_proof_tampered_attestation_fails():
    root = _root()
    child = _child(root)
    proof = create_blind_proof(root, child)
    bad = LinkageProof(
        master_pubkey=proof.master_pubkey,
        child_pubkey=proof.child_pubkey,
        attestation=proof.attestation + "X",
        signature=proof.signature,
    )
    assert verify_proof(bad) is False


def test_blind_proof_tampered_signature_fails():
    root = _root()
    child = _child(root)
    proof = create_blind_proof(root, child)
    # Flip the last hex char
    flipped = proof.signature[:-1] + ("0" if proof.signature[-1] != "0" else "1")
    bad = LinkageProof(
        master_pubkey=proof.master_pubkey,
        child_pubkey=proof.child_pubkey,
        attestation=proof.attestation,
        signature=flipped,
    )
    assert verify_proof(bad) is False


# ---------------------------------------------------------------------------
# Roundtrip — full proof
# ---------------------------------------------------------------------------

def test_full_proof_roundtrip():
    root = _root()
    child = _child(root)
    proof = create_full_proof(root, child)
    assert verify_proof(proof) is True


def test_full_proof_tampered_attestation_fails():
    root = _root()
    child = _child(root)
    proof = create_full_proof(root, child)
    bad = LinkageProof(
        master_pubkey=proof.master_pubkey,
        child_pubkey=proof.child_pubkey,
        attestation=proof.attestation.replace("|0", "|1"),
        signature=proof.signature,
        purpose=proof.purpose,
        index=proof.index,
    )
    assert verify_proof(bad) is False


def test_full_proof_tampered_signature_fails():
    root = _root()
    child = _child(root)
    proof = create_full_proof(root, child)
    flipped = proof.signature[:-1] + ("0" if proof.signature[-1] != "0" else "1")
    bad = LinkageProof(
        master_pubkey=proof.master_pubkey,
        child_pubkey=proof.child_pubkey,
        attestation=proof.attestation,
        signature=flipped,
        purpose=proof.purpose,
        index=proof.index,
    )
    assert verify_proof(bad) is False


# ---------------------------------------------------------------------------
# Determinism (zero-aux)
# ---------------------------------------------------------------------------

def test_blind_proof_is_deterministic():
    root = _root()
    child = _child(root)
    p1 = create_blind_proof(root, child)
    p2 = create_blind_proof(root, child)
    assert p1.signature == p2.signature


def test_full_proof_is_deterministic():
    root = _root()
    child = _child(root)
    p1 = create_full_proof(root, child)
    p2 = create_full_proof(root, child)
    assert p1.signature == p2.signature


# ---------------------------------------------------------------------------
# Proof-purpose rejection
# ---------------------------------------------------------------------------

def test_full_proof_rejects_pipe_in_purpose():
    root = _root()
    # derive allows any purpose; validate_proof_purpose catches pipe
    child_bad = derive(root, "bad|purpose", 0)
    with pytest.raises(InvalidPurpose):
        create_full_proof(root, child_bad)


# ---------------------------------------------------------------------------
# Canonical mismatch / structural invalidity
# ---------------------------------------------------------------------------

def test_verify_proof_rejects_mismatched_attestation():
    root = _root()
    child = _child(root)
    proof = create_blind_proof(root, child)
    # Replace .attestation with an unrelated string (canonical won't match)
    bad = LinkageProof(
        master_pubkey=proof.master_pubkey,
        child_pubkey=proof.child_pubkey,
        attestation="something-else",
        signature=proof.signature,
    )
    assert verify_proof(bad) is False


def test_verify_proof_rejects_purpose_without_index():
    root = _root()
    child = _child(root)
    proof = create_blind_proof(root, child)
    bad = LinkageProof(
        master_pubkey=proof.master_pubkey,
        child_pubkey=proof.child_pubkey,
        attestation=proof.attestation,
        signature=proof.signature,
        purpose="social",   # purpose set but index is None → structurally invalid
        index=None,
    )
    assert verify_proof(bad) is False


def test_verify_proof_rejects_index_without_purpose():
    root = _root()
    child = _child(root)
    proof = create_blind_proof(root, child)
    bad = LinkageProof(
        master_pubkey=proof.master_pubkey,
        child_pubkey=proof.child_pubkey,
        attestation=proof.attestation,
        signature=proof.signature,
        purpose=None,       # index set but purpose is None → structurally invalid
        index=0,
    )
    assert verify_proof(bad) is False


# ---------------------------------------------------------------------------
# Wire format serialisation
# ---------------------------------------------------------------------------

def test_proof_to_dict_from_dict_roundtrip():
    root = _root()
    child = _child(root)
    proof = create_full_proof(root, child)
    d = proof_to_dict(proof)
    assert proof_from_dict(d) == proof


# ---------------------------------------------------------------------------
# FROZEN @noble interop fixtures — genuine TypeScript/@noble signatures
# These MUST verify in Python — permanent cross-impl conformance gate.
# ---------------------------------------------------------------------------

TS_BLIND = {
    "masterPubkey": "8c03e047ae60c01e942a8337e71d17e3517fcc63ee6ceff8173bbd23fabe649d",
    "childPubkey": "cdc4cd2a01ba1b8afd3299b66c38d13043a19acb687c334f0527cffaf464b372",
    "attestation": "nsec-tree:own|8c03e047ae60c01e942a8337e71d17e3517fcc63ee6ceff8173bbd23fabe649d|cdc4cd2a01ba1b8afd3299b66c38d13043a19acb687c334f0527cffaf464b372",
    "signature": "a2d5478ee7fa453a3972e837982434639bf045ffa53b17d3be055cd5a471c500b875bbbb90cc03335492e62ff4af6e97e78dbd752efde7842b3cde18e05b52f8",
}

TS_FULL = {
    "masterPubkey": "8c03e047ae60c01e942a8337e71d17e3517fcc63ee6ceff8173bbd23fabe649d",
    "childPubkey": "cdc4cd2a01ba1b8afd3299b66c38d13043a19acb687c334f0527cffaf464b372",
    "purpose": "social",
    "index": 0,
    "attestation": "nsec-tree:link|8c03e047ae60c01e942a8337e71d17e3517fcc63ee6ceff8173bbd23fabe649d|cdc4cd2a01ba1b8afd3299b66c38d13043a19acb687c334f0527cffaf464b372|social|0",
    "signature": "a2f7797cef1d0ae98a9ffd45e06b5e0e14c7ad3b868827b092b750c00f73f5ddc64636701a8c00f6366bd0dd254788051efa75a68001ac14e214012ae058b89d",
}


def test_noble_blind_fixture_verifies():
    """TypeScript/@noble blind-proof signature MUST verify in Python."""
    assert verify_proof(proof_from_dict(TS_BLIND)) is True


def test_noble_full_fixture_verifies():
    """TypeScript/@noble full-proof signature MUST verify in Python."""
    assert verify_proof(proof_from_dict(TS_FULL)) is True


def test_noble_full_wire_roundtrip():
    """proof_to_dict(proof_from_dict(TS_FULL)) must equal TS_FULL exactly."""
    assert proof_to_dict(proof_from_dict(TS_FULL)) == TS_FULL


# ---------------------------------------------------------------------------
# Trailing-newline strictness — Python's `$` matches before a trailing "\n"
# but JavaScript's `$` does not; the hex validators anchor with `\Z` so a
# trailing-newline key is rejected like the TS reference. (Cross-impl parity.)
# ---------------------------------------------------------------------------

def test_canonical_attestation_rejects_trailing_newline_pubkey():
    root = _root()
    proof = create_blind_proof(root, _child(root))
    bad = LinkageProof(
        master_pubkey=proof.master_pubkey + "\n",
        child_pubkey=proof.child_pubkey,
        attestation=proof.attestation,
        signature=proof.signature,
    )
    assert canonical_attestation(bad) is None
    assert verify_proof(bad) is False
