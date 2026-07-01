"""nsec-tree — deterministic Nostr sub-identity derivation (NIP-IDENTITY-TREES)."""
from .root import from_nsec, TreeRoot, zeroise
from .derive import derive, Identity
from .persona import derive_persona, derive_from_identity
from .recover import recover
from .errors import NsecTreeError, InvalidKey, InvalidPurpose, IndexOverflow
from .proof import (
    LinkageProof,
    create_blind_proof,
    create_full_proof,
    verify_proof,
    proof_to_dict,
    proof_from_dict,
)
from .event import (
    UnsignedEvent,
    to_unsigned_event,
    from_event,
    NSEC_TREE_EVENT_KIND,
    NSEC_TREE_D_PREFIX,
)
from . import encoding

__version__ = "0.1.0"
__all__ = [
    "from_nsec",
    "TreeRoot",
    "zeroise",
    "derive",
    "Identity",
    "derive_persona",
    "derive_from_identity",
    "recover",
    "encoding",
    "NsecTreeError",
    "InvalidKey",
    "InvalidPurpose",
    "IndexOverflow",
    "LinkageProof",
    "create_blind_proof",
    "create_full_proof",
    "verify_proof",
    "proof_to_dict",
    "proof_from_dict",
    "UnsignedEvent",
    "to_unsigned_event",
    "from_event",
    "NSEC_TREE_EVENT_KIND",
    "NSEC_TREE_D_PREFIX",
]
