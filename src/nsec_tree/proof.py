"""Linkage proofs — PROTOCOL.md §5 (blind and full Schnorr attestations)."""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

from .derive import Identity
from .keys import schnorr_sign, schnorr_verify
from .root import TreeRoot
from .validate import validate_proof_purpose

_MAX_INDEX = 0xFFFFFFFF
_HEX_KEY = re.compile(r"^[0-9a-f]{64}$")
_HEX_SIG = re.compile(r"^[0-9a-f]{128}$")


@dataclass(frozen=True)
class LinkageProof:
    master_pubkey: str          # lowercase hex x-only (64)
    child_pubkey: str           # lowercase hex x-only (64)
    attestation: str
    signature: str              # lowercase hex (128)
    purpose: str | None = None  # full proofs only
    index: int | None = None    # full proofs only


def _blind_attestation(master_hex: str, child_hex: str) -> str:
    return f"nsec-tree:own|{master_hex}|{child_hex}"


def _full_attestation(master_hex: str, child_hex: str, purpose: str, index: int) -> str:
    return f"nsec-tree:link|{master_hex}|{child_hex}|{purpose}|{index}"


def create_blind_proof(root: TreeRoot, child: Identity) -> LinkageProof:
    master_hex = root.master_pubkey.hex()
    child_hex = child.public_key.hex()
    attestation = _blind_attestation(master_hex, child_hex)
    signature = schnorr_sign(root.secret, attestation.encode("utf-8")).hex()
    return LinkageProof(master_hex, child_hex, attestation, signature)


def create_full_proof(root: TreeRoot, child: Identity) -> LinkageProof:
    validate_proof_purpose(child.purpose)
    master_hex = root.master_pubkey.hex()
    child_hex = child.public_key.hex()
    attestation = _full_attestation(master_hex, child_hex, child.purpose, child.index)
    signature = schnorr_sign(root.secret, attestation.encode("utf-8")).hex()
    return LinkageProof(master_hex, child_hex, attestation, signature, child.purpose, child.index)


def canonical_attestation(proof: LinkageProof) -> str | None:
    """Rebuild the canonical attestation from a proof's fields, or None if the
    fields are structurally invalid. Mirrors the reference implementation.
    """
    if not _HEX_KEY.match(proof.master_pubkey) or not _HEX_KEY.match(proof.child_pubkey):
        return None
    has_purpose = proof.purpose is not None
    has_index = proof.index is not None
    if has_purpose != has_index:
        return None
    if not has_purpose:
        return _blind_attestation(proof.master_pubkey, proof.child_pubkey)
    if not isinstance(proof.index, int) or isinstance(proof.index, bool):
        return None
    if proof.index < 0 or proof.index > _MAX_INDEX:
        return None
    try:
        validate_proof_purpose(proof.purpose)  # type: ignore[arg-type]
    except Exception:
        return None
    return _full_attestation(proof.master_pubkey, proof.child_pubkey, proof.purpose, proof.index)  # type: ignore[arg-type]


def verify_proof(proof: LinkageProof) -> bool:
    try:
        attestation = canonical_attestation(proof)
        if attestation is None or attestation != proof.attestation:
            return False
        if not _HEX_SIG.match(proof.signature):
            return False
        return schnorr_verify(
            bytes.fromhex(proof.master_pubkey),
            bytes.fromhex(proof.signature),
            attestation.encode("utf-8"),
        )
    except Exception:
        return False


def proof_to_dict(proof: LinkageProof) -> dict[str, object]:
    """Serialise to the wire format (camelCase keys) exchanged with other impls."""
    d: dict[str, object] = {"masterPubkey": proof.master_pubkey, "childPubkey": proof.child_pubkey}
    if proof.purpose is not None:
        d["purpose"] = proof.purpose
        d["index"] = proof.index
    d["attestation"] = proof.attestation
    d["signature"] = proof.signature
    return d


def proof_from_dict(d: dict[str, Any]) -> LinkageProof:
    return LinkageProof(
        master_pubkey=d["masterPubkey"],
        child_pubkey=d["childPubkey"],
        attestation=d["attestation"],
        signature=d["signature"],
        purpose=d.get("purpose"),
        index=d.get("index"),
    )
