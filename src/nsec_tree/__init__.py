"""nsec-tree — deterministic Nostr sub-identity derivation (NIP-IDENTITY-TREES)."""
from .root import from_nsec, TreeRoot, zeroise
from .mnemonic import from_mnemonic
from .derive import derive, Identity
from .persona import (
    Persona,
    derive_persona,
    derive_from_identity,
    derive_from_persona,
    recover_personas,
    validate_persona_name,
    DEFAULT_PERSONA_NAMES,
    MAX_INDEX,
    DEFAULT_SCAN_RANGE,
    MAX_SCAN_RANGE,
    MAX_RECOVERY_PURPOSES,
)
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
    "from_mnemonic",
    "TreeRoot",
    "zeroise",
    "derive",
    "Identity",
    "Persona",
    "derive_persona",
    "derive_from_identity",
    "derive_from_persona",
    "recover_personas",
    "validate_persona_name",
    "DEFAULT_PERSONA_NAMES",
    "MAX_INDEX",
    "DEFAULT_SCAN_RANGE",
    "MAX_SCAN_RANGE",
    "MAX_RECOVERY_PURPOSES",
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
