# nsec-tree-py

Python implementation of the nsec-tree protocol (NIP-IDENTITY-TREES):
deterministic derivation of a tree of independent secp256k1 Nostr sub-
identities from a single master `nsec`. Each child is bound to a
human-readable purpose string and numeric index, cryptographically
unlinkable without an explicit linkage proof. Derivation is cross-verified
byte-for-byte against the TypeScript and Rust reference implementations.

## Build & Test

| Command | Purpose |
|---------|---------|
| `pip install -e ".[dev,mnemonic]"` | Install with dev and mnemonic extras |
| `pytest --cov=nsec_tree --cov-report=term-missing --cov-fail-under=90` | Run tests with coverage |
| `ruff check .` | Lint |
| `mypy src` | Type-check |

CI (`.github/workflows/ci.yml`) runs this matrix on Python 3.11, 3.12 and
3.13; 3.13 skips the mnemonic extra (coincurve has no source build path
there for the pinned `bip32` constraint).

## Structure

```
src/nsec_tree/
  root.py        TreeRoot, from_nsec, zeroise
  derive.py       derive(), Identity
  persona.py      derive_persona, recover_personas, persona namespace
  proof.py        linkage proofs (blind and full), verify_proof
  event.py        NIP-78 event encode/decode
  recover.py      recover() across purposes/indices
  mnemonic.py     from_mnemonic (BIP-39 -> BIP-32 entry point, optional extra)
  encoding.py     bech32 nsec/npub helpers
  validate.py     purpose-string and index validation
  errors.py       NsecTreeError and subclasses
tests/            pytest suite, including tests/vectors (frozen cross-implementation vectors)
tools/            gen_reference_vectors.mjs, a Node script that regenerates tests/vectors
  from the TypeScript reference implementation
```

## Conventions

- British English in prose; American English is acceptable in code identifiers
  matching upstream protocol naming.
- Purpose strings are non-empty, at most 255 bytes, contain no null bytes, and
  are not whitespace-only; case-sensitive and byte-exact.
- The mnemonic path (BIP-39 -> BIP-32 `m/44'/1237'/727'/0'/0'`) and the nsec
  path produce different tree roots from the same secret; they are not
  interchangeable.
- No secret-dependent equality comparisons; no secret material in exceptions
  or tracebacks (see SECURITY.md).

## Key Files

| File | Purpose |
|------|---------|
| `src/nsec_tree/__init__.py` | public API surface (`__all__`) |
| `PROTOCOL.md` (in the `nsec-tree` spec repo) | the protocol this implements |
| `SECURITY.md` | threat model and audit status |
| `tests/vectors/` | frozen cross-implementation differential vectors |

## Common Pitfalls

- Do not change values in `tests/vectors/`: they are frozen and asserted
  byte-for-byte against the TypeScript reference. Regenerate only via
  `tools/gen_reference_vectors.mjs` if the protocol itself changes.
- The raw nsec is never used directly as the derivation key; `from_nsec`
  HMACs it first to separate the signing key from the tree root.
- `derive`'s returned `index` may differ from the requested one if a
  curve-order retry fired; do not assume it echoes the input unchanged.
- Not independently audited; review before protecting high-value keys.
