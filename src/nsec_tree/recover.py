"""Scan-based recovery: re-derive known purposes across an index range."""
from __future__ import annotations

from .derive import Identity, derive
from .errors import InvalidPurpose
from .persona import MAX_RECOVERY_PURPOSES, MAX_SCAN_RANGE
from .root import TreeRoot


def recover(
    root: TreeRoot, purposes: list[str], scan_range: int = 20
) -> dict[str, list[Identity]]:
    """Derive identities for each purpose across an index range.

    Args:
        root: The tree root to derive from.
        purposes: List of purpose strings to recover.
        scan_range: Number of indices to scan (0..scan_range-1).

    Returns:
        A dict mapping each purpose to a list of derived identities.
    """
    if not isinstance(purposes, list):
        raise InvalidPurpose("purposes must be a list")
    if len(purposes) > MAX_RECOVERY_PURPOSES:
        raise InvalidPurpose(f"purposes must not exceed {MAX_RECOVERY_PURPOSES} entries")
    if isinstance(scan_range, bool) or not isinstance(scan_range, int) or not (0 <= scan_range <= MAX_SCAN_RANGE):
        raise InvalidPurpose(f"scan_range must be an int in [0, {MAX_SCAN_RANGE}]")
    return {p: [derive(root, p, i) for i in range(scan_range)] for p in purposes}
