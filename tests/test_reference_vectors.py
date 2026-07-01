"""Byte-parity against the frozen TS v1.5.1 reference matrix (tests/vectors/ts_reference.json).

Every public function is cross-checked: derive, derive_from_identity, derive_persona,
derive_from_persona, proof round-trips, event round-trips, and from_mnemonic.
No Node.js is required at test time — the JSON is committed and frozen.
"""
import json
from pathlib import Path

import pytest

import nsec_tree
from nsec_tree import derive, derive_from_identity, derive_from_persona, derive_persona, from_nsec
from nsec_tree.event import from_event
from nsec_tree.proof import proof_from_dict, verify_proof

REF = json.loads((Path(__file__).parent / "vectors" / "ts_reference.json").read_text())
CASES = REF["cases"]


def _root(hex_: str) -> nsec_tree.TreeRoot:
    return from_nsec(bytes.fromhex(hex_))


# ---------------------------------------------------------------------------
# derive — 30 cases (3 nsecs × 5 purposes × 2 indices)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "c",
    CASES["derive"],
    ids=lambda c: f'{c["nsec_hex"][:4]}:{c["purpose"][:8]}:{c["index"]}',
)
def test_derive_matches_ts(c: dict) -> None:
    child = derive(_root(c["nsec_hex"]), c["purpose"], c["index"])
    assert child.npub == c["npub"]
    assert child.nsec == c["nsec"]
    assert child.public_key.hex() == c["pub"]
    assert child.index == c["index"]


# ---------------------------------------------------------------------------
# derive_from_identity — 3 cases (one per nsec, parent=social, child=commerce)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "c",
    CASES["derive_from_identity"],
    ids=lambda c: c["nsec_hex"][:8],
)
def test_hierarchy_matches_ts(c: dict) -> None:
    social = derive(_root(c["nsec_hex"]), c["parent"], 0)
    sub = derive_from_identity(social, c["purpose"], 0)
    assert sub.npub == c["npub"]
    assert sub.nsec == c["nsec"]
    assert sub.public_key.hex() == c["pub"]


# ---------------------------------------------------------------------------
# derive_persona — 9 cases (3 nsecs × 3 persona names)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "c",
    CASES["derive_persona"],
    ids=lambda c: f'{c["nsec_hex"][:4]}:{c["name"]}',
)
def test_persona_matches_ts(c: dict) -> None:
    p = derive_persona(_root(c["nsec_hex"]), c["name"], 0)
    assert p.identity.npub == c["npub"]
    assert p.identity.nsec == c["nsec"]
    assert p.identity.public_key.hex() == c["pub"]


# ---------------------------------------------------------------------------
# derive_from_persona — 9 cases (3 nsecs × 3 names, sub-purpose = payroll)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "c",
    CASES["derive_from_persona"],
    ids=lambda c: f'{c["nsec_hex"][:4]}:{c["name"]}',
)
def test_persona_sub_matches_ts(c: dict) -> None:
    p = derive_persona(_root(c["nsec_hex"]), c["name"], 0)
    sub = derive_from_persona(p, c["purpose"], 0)
    assert sub.npub == c["npub"]
    assert sub.nsec == c["nsec"]
    assert sub.public_key.hex() == c["pub"]


# ---------------------------------------------------------------------------
# blind_proof — 3 cases: TS-generated Schnorr sigs over nsec-tree:own|… attestation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("c", CASES["blind_proof"], ids=lambda c: c["nsec_hex"][:8])
def test_blind_proof_matches_ts(c: dict) -> None:
    proof = proof_from_dict({k: c[k] for k in ("masterPubkey", "childPubkey", "attestation", "signature")})
    assert verify_proof(proof) is True


# ---------------------------------------------------------------------------
# full_proof — 3 cases: reconstruct from dict, verify signature
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "c",
    CASES["full_proof"],
    ids=lambda c: c["nsec_hex"][:8],
)
def test_full_proof_matches_ts(c: dict) -> None:
    proof = proof_from_dict(
        {k: c[k] for k in ("masterPubkey", "childPubkey", "purpose", "index", "attestation", "signature")}
    )
    assert verify_proof(proof) is True


# ---------------------------------------------------------------------------
# event — 3 cases: round-trip from_event → verify_proof
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "c",
    CASES["event"],
    ids=lambda c: c["nsec_hex"][:8],
)
def test_event_from_ts_verifies(c: dict) -> None:
    proof = from_event({"pubkey": c["pubkey"], "tags": c["tags"]})
    assert verify_proof(proof) is True


# ---------------------------------------------------------------------------
# from_mnemonic — 1 case, skipped if [mnemonic] extra not installed
# ---------------------------------------------------------------------------

def test_from_mnemonic_matches_ts() -> None:
    pytest.importorskip("mnemonic")
    c = CASES["from_mnemonic"][0]
    root = nsec_tree.from_mnemonic(c["mnemonic"])
    child = derive(root, "social", 0)
    assert child.npub == c["social"]["npub"]
    assert child.nsec == c["social"]["nsec"]
    assert child.public_key.hex() == c["social"]["pub"]
