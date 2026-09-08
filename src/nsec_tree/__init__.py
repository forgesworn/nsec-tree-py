"""nsec-tree — deterministic Nostr sub-identity derivation (NIP-IDENTITY-TREES)."""
from . import encoding
from .derive import Identity, derive
from .errors import IndexOverflow, InvalidKey, InvalidPurpose, NsecTreeError
from .event import (
    NSEC_TREE_D_PREFIX,
    NSEC_TREE_EVENT_KIND,
    UnsignedEvent,
    from_event,
    to_unsigned_event,
)
from .mnemonic import from_mnemonic
from .persona import (
    DEFAULT_PERSONA_NAMES,
    DEFAULT_SCAN_RANGE,
    MAX_INDEX,
    MAX_RECOVERY_PURPOSES,
    MAX_SCAN_RANGE,
    Persona,
    derive_from_identity,
    derive_from_persona,
    derive_persona,
    recover_personas,
    validate_persona_name,
)
from .proof import (
    LinkageProof,
    create_blind_proof,
    create_full_proof,
    proof_from_dict,
    proof_to_dict,
    verify_proof,
)
from .recover import recover
from .root import TreeRoot, from_nsec, zeroise

__version__ = "1.0.1"
__all__ = [
    "DEFAULT_PERSONA_NAMES",
    "DEFAULT_SCAN_RANGE",
    "MAX_INDEX",
    "MAX_RECOVERY_PURPOSES",
    "MAX_SCAN_RANGE",
    "NSEC_TREE_D_PREFIX",
    "NSEC_TREE_EVENT_KIND",
    "Identity",
    "IndexOverflow",
    "InvalidKey",
    "InvalidPurpose",
    "LinkageProof",
    "NsecTreeError",
    "Persona",
    "TreeRoot",
    "UnsignedEvent",
    "create_blind_proof",
    "create_full_proof",
    "derive",
    "derive_from_identity",
    "derive_from_persona",
    "derive_persona",
    "encoding",
    "from_event",
    "from_mnemonic",
    "from_nsec",
    "proof_from_dict",
    "proof_to_dict",
    "recover",
    "recover_personas",
    "to_unsigned_event",
    "validate_persona_name",
    "verify_proof",
    "zeroise",
]
