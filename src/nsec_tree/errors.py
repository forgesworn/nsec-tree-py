"""Shared exception hierarchy for nsec-tree."""
from __future__ import annotations


class NsecTreeError(Exception): ...


class InvalidKey(NsecTreeError): ...


class InvalidPurpose(NsecTreeError): ...


class IndexOverflow(NsecTreeError): ...
