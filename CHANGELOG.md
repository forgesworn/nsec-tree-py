# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/).

## [1.0.0] — 2026-07-01

### Added

- `from_mnemonic` (BIP-39/BIP-32 entry point) behind the optional `[mnemonic]` extra.
- Persona batch helpers: `Persona`, `derive_from_persona`, `recover_personas`,
  `DEFAULT_PERSONA_NAMES`, and the `MAX_INDEX`/`DEFAULT_SCAN_RANGE`/`MAX_SCAN_RANGE`/`MAX_RECOVERY_PURPOSES` constants.
- NIP-78 event conversion (`to_unsigned_event`/`from_event`).
- Frozen TS-reference differential vectors and `hypothesis` parser fuzzing.
- `SECURITY.md`.

### Changed (breaking)

- **`derive_persona` now returns `Persona {identity, name, index}`**, not a bare
  `Identity`. Migration: use `derive_persona(root, name).identity`.
- **`derive_from_identity` now HMACs the parent key through `from_nsec`** before
  deriving, matching the reference. Hierarchy keys derived with 0.x differ.

### Fixed

- Hex/uint validators anchor with `\Z` (were `$`), rejecting trailing newlines
  to match the reference exactly.

### Security

- Bounded `recover()` inputs: `purposes` count is now capped at `MAX_RECOVERY_PURPOSES`
  and `scan_range` is capped at `MAX_SCAN_RANGE`, preventing unbounded computation —
  consistent with the existing bounds on `recover_personas`.
- Public entry points now raise typed `NsecTreeError`-family errors instead of raw
  built-in exceptions:
  - `from_event`: raises `NsecTreeError` on missing `pubkey`/`tags`, non-list `tags`,
    and oversized index (was `KeyError`/`TypeError`/`ValueError`).
  - `derive`: rejects non-integer and `bool` index values (`InvalidKey`), and raises
    `IndexOverflow` on out-of-range indices (was `OverflowError`/`AttributeError`).
    Both are `NsecTreeError` subtypes.
  - `from_nsec`: raises `InvalidKey` on non-str/bytes/bytearray input
    (`NsecTreeError` subtype; was `TypeError`).
  - Non-string purpose values now raise `InvalidPurpose` (`NsecTreeError` subtype)
    across all entry points (was `TypeError`/`AttributeError`).
