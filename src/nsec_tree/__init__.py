"""nsec-tree — deterministic Nostr sub-identity derivation (NIP-IDENTITY-TREES)."""
from .root import from_nsec, TreeRoot, zeroise
from .derive import derive, Identity
from .persona import derive_persona, derive_from_identity
from .recover import recover
from .errors import NsecTreeError, InvalidKey, InvalidPurpose, IndexOverflow
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
]
