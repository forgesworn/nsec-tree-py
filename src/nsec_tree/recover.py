"""Scan-based recovery: re-derive known purposes across an index range."""
from __future__ import annotations

from .derive import Identity, derive
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
    return {p: [derive(root, p, i) for i in range(scan_range)] for p in purposes}
