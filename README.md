# nsec-tree-py

[![PyPI](https://img.shields.io/pypi/v/nsec-tree)](https://pypi.org/project/nsec-tree/)
[![Python](https://img.shields.io/pypi/pyversions/nsec-tree)](https://pypi.org/project/nsec-tree/)
[![CI](https://github.com/forgesworn/nsec-tree-py/actions/workflows/ci.yml/badge.svg)](https://github.com/forgesworn/nsec-tree-py/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

Deterministic Nostr sub-identity derivation — Python implementation of the
[nsec-tree protocol](https://github.com/forgesworn/nsec-tree/blob/main/PROTOCOL.md)
(NIP-IDENTITY-TREES `v1.1`).

Derives a tree of independent secp256k1 key pairs from a single master nsec.
Each child key is a fully usable Nostr identity (nsec + npub) bound to a
human-readable **purpose** string and a numeric **index**. Children are
cryptographically unlinkable without an explicit linkage proof.

- **Deterministic and cross-implementation.** The same `(purpose, index)` yields the
  same key in the Python, TypeScript, and Rust implementations — asserted byte-for-byte
  by a frozen 61-case differential suite against the TypeScript v1.5.1 reference.
- **Two entry points.** Derive from a Nostr `nsec`, or from a BIP-39 mnemonic
  (`pip install nsec-tree[mnemonic]`).
- **Unlinkable children, provable on demand.** Independent identities that link only
  with an explicit BIP-340 Schnorr **linkage proof** (blind or full), publishable as a
  NIP-78 event.
- **Typed and lean.** Ships `py.typed`; depends only on `coincurve` and `bech32`. MIT.

> **Status: `1.0.0`** — conformance-tested against the full frozen vector suite (§6.1–6.6),
> cross-verified against the TypeScript reference, not independently audited.
> Semantic versioning; breaking changes only on major bumps.
> See [Status & security](#status--security) before using it to protect high-value keys.

---

## Install

```bash
pip install nsec-tree
```

Requires Python 3.11 or later.

### Mnemonic entry point (optional)

```bash
pip install nsec-tree[mnemonic]
```

```python
root = nsec_tree.from_mnemonic("abandon abandon ... about")
```

The mnemonic path (BIP-39 → BIP-32 `m/44'/1237'/727'/0'/0'`) and the nsec path
produce **different** tree roots from the same secret — choose one entry point.

---

## Quick start

### 1. Build a tree root from your nsec

```python
import nsec_tree

root = nsec_tree.from_nsec("nsec1...")

print(root.master_npub)  # the root's public identity
```

The raw nsec bytes are never used directly as the derivation key — a
one-way HMAC step creates separation between your signing key and the tree
root (PROTOCOL.md §1.2).

### 2. Derive a sub-identity

```python
# Derive a child key for a purpose string and index
social = nsec_tree.derive(root, "social")          # index 0 by default
commerce = nsec_tree.derive(root, "commerce", 0)

print(social.nsec)    # bech32 nsec — use as a Nostr signing key
print(social.npub)    # bech32 npub — share as your Nostr public key
print(social.purpose) # "social"
print(social.index)   # 0 (may differ from requested if curve-order retry fired)
```

Any purpose string works as long as it is non-empty, at most 255 bytes,
contains no null bytes, and is not whitespace-only. Purpose strings are
case-sensitive and byte-exact.

### 3. Derive a named persona

A persona is a convenience wrapper over `derive` that uses the reserved
`nostr:persona:<name>` namespace:

```python
writer = nsec_tree.derive_persona(root, "writer")
print(writer.name)          # "writer"
print(writer.identity.npub) # the derived Nostr identity

# Recover known personas across an index range
found = nsec_tree.recover_personas(root, ["writer", "work"], scan_range=5)
```

Personas derived with the same name in any conformant nsec-tree implementation
(TypeScript, Rust, Python) produce identical keys.

### 4. Derive from an existing identity (hierarchy)

```python
# Add a layer beneath an existing child — the child's private key becomes
# the HMAC key for the next derivation.
social = nsec_tree.derive(root, "social")
sub = nsec_tree.derive_from_identity(social, "commerce")
```

### 5. Recover known purposes

Scan a range of indices to reconstruct previously derived identities from
a list of known purpose strings:

```python
recovered = nsec_tree.recover(root, ["social", "commerce"], scan_range=20)

for purpose, identities in recovered.items():
    for identity in identities:
        print(identity.index, identity.npub)
```

### 6. Encode and decode keys

```python
# Raw bytes ↔ bech32 nsec / npub
raw = nsec_tree.encoding.decode_nsec(social.nsec)
back = nsec_tree.encoding.encode_nsec(raw)  # roundtrips exactly

pub_raw = nsec_tree.encoding.decode_npub(social.npub)
```

### 7. Linkage proofs

A linkage proof lets the master identity prove ownership of a child key — either
*blind* (proving ownership without revealing purpose/index) or *full* (revealing
the derivation parameters). Proofs are BIP-340 Schnorr signatures over a
pipe-delimited attestation string, **cross-verified interoperable with the
TypeScript `nsec-tree` (@noble) implementation**.

```python
import nsec_tree

root = nsec_tree.from_nsec("nsec1...")
child = nsec_tree.derive(root, "social")

# Blind proof — proves master → child without revealing purpose or index
blind = nsec_tree.create_blind_proof(root, child)
assert nsec_tree.verify_proof(blind)

# Full proof — reveals purpose and index
full = nsec_tree.create_full_proof(root, child)
assert nsec_tree.verify_proof(full)

# Serialise / deserialise (camelCase wire format, compatible with TS impl)
wire = nsec_tree.proof_to_dict(full)
restored = nsec_tree.proof_from_dict(wire)
assert nsec_tree.verify_proof(restored)
```

### 8. Publish a proof as a Nostr event (NIP-78)

A linkage proof can be wrapped as an unsigned NIP-78 (Kind `30078`) Nostr event,
signed and published with your own Nostr library, then parsed back later. The tag
layout is interoperable with the TypeScript `nsec-tree` implementation.

```python
import dataclasses
import nsec_tree

root = nsec_tree.from_nsec("nsec1...")
child = nsec_tree.derive(root, "social")
proof = nsec_tree.create_full_proof(root, child)

# Wrap → an unsigned event; sign/publish it with your Nostr client
event = nsec_tree.to_unsigned_event(proof)
event_dict = dataclasses.asdict(event)   # {kind, pubkey, created_at, tags, content}

# Parse a received event back into a proof, then verify
restored = nsec_tree.from_event(event_dict)   # also accepts the UnsignedEvent directly
assert nsec_tree.verify_proof(restored)
```

`to_unsigned_event` does not sign — it produces the unsigned event for your Nostr
library to finalise. `from_event` rejects duplicate nsec-tree tags (a
"duplicate-tag smuggling" guard) and malformed fields.

### 9. Zeroisation

Call `zeroise` to clear an identity's private key. This is best-effort —
CPython cannot scrub immutable `bytes`/`str` in place; `zeroise` rebinds both
`private_key` and `nsec` to cleared values and drops the references:

```python
nsec_tree.zeroise(social)
```

Call `root.destroy()` to wipe the tree root secret:

```python
root.destroy()
```

---

## API reference

### `from_nsec(nsec: str | bytes) -> TreeRoot`

Build a tree root from a bech32 `nsec` string or raw 32-byte key material.

### `from_mnemonic(mnemonic: str, passphrase: str | None = None) -> TreeRoot`

Build a tree root from a BIP-39 mnemonic phrase. Requires `pip install nsec-tree[mnemonic]`.
Derives at `m/44'/1237'/727'/0'/0'` (all hardened); the resulting key is used directly as
the tree-root secret (no extra HMAC — distinct from `from_nsec`).
Raises `NsecTreeError` if the extra is not installed or the mnemonic is invalid.

### `TreeRoot`

| Attribute | Type | Description |
|-----------|------|-------------|
| `secret` | `bytes` | 32-byte tree root secret (sensitive) |
| `master_pubkey` | `bytes` | x-only public key (32 bytes) |
| `master_npub` | `str` | bech32 npub of the master identity |

`root.destroy()` is best-effort — rebinds `secret` to null bytes; CPython cannot scrub the original `bytes` object in place.

### `derive(root, purpose, index=0) -> Identity`

Derive a child identity. Raises `IndexOverflow` if every index up to
`0xFFFFFFFF` fails the curve-order check (astronomically unlikely in practice).

### `derive_persona(root, name, index=0) -> Persona`

Derive the child at purpose `nostr:persona:<name>`. Returns a `Persona` — see below.

### `Persona`

| Attribute | Type | Description |
|-----------|------|-------------|
| `identity` | `Identity` | The derived Nostr identity |
| `name` | `str` | The persona name (without the `nostr:persona:` prefix) |
| `index` | `int` | Actual index used (may be higher than requested) |

`Persona` is frozen (immutable). Access the Nostr keys via `persona.identity.nsec` / `persona.identity.npub`.

### `derive_from_persona(persona, purpose, index=0) -> Identity`

Derive a sub-identity within a persona (two-level hierarchy). Uses the persona's
private key as the HMAC key for a further derivation step — matching
`derive_from_identity` but taking a `Persona` directly.

### `recover_personas(root, names=DEFAULT_PERSONA_NAMES, scan_range=1) -> dict[str, list[Persona]]`

Scan a range of indices to reconstruct previously derived personas from a list
of known names. Returns a dict mapping each name to a list of `Persona` objects
for indices `0 .. scan_range-1`. `names` defaults to `DEFAULT_PERSONA_NAMES`
(`personal`, `bitcoiner`, `work`, `social`, `anonymous`).

### `derive_from_identity(identity, purpose, index=0) -> Identity`

Use `identity.private_key` as the HMAC key for a further derivation step.

### `recover(root, purposes, scan_range=20) -> dict[str, list[Identity]]`

Return a dict mapping each purpose to a list of `Identity` objects for indices
`0 .. scan_range-1`.

### `Identity`

| Attribute | Type | Description |
|-----------|------|-------------|
| `private_key` | `bytes` | 32-byte private key (sensitive) |
| `public_key` | `bytes` | x-only public key (32 bytes) |
| `nsec` | `str` | bech32 nsec |
| `npub` | `str` | bech32 npub |
| `purpose` | `str` | Purpose string used in derivation |
| `index` | `int` | Actual index used (may be higher than requested) |

`Identity` is frozen (immutable). Call `zeroise(identity)` for best-effort
secret clearance — see `zeroise` below.

### `zeroise(identity: Identity) -> None`

Best-effort secret clearance — rebinds `private_key` to null bytes and `nsec`
to `""`. CPython cannot scrub immutable `bytes`/`str` in place; the attribute
is merely rebound and the original key material remains in memory until the
garbage collector reclaims it.

### `create_blind_proof(root, child) -> LinkageProof`

Create a blind linkage proof — proves that the master key owns the child key
without revealing the purpose string or index.

### `create_full_proof(root, child) -> LinkageProof`

Create a full linkage proof — reveals purpose and index alongside the Schnorr
attestation. Raises `InvalidPurpose` if the purpose contains `|` or control
characters (which would break the pipe-delimited attestation format).

### `verify_proof(proof: LinkageProof) -> bool`

Verify a linkage proof. Returns `False` (never raises) for any invalid or
tampered proof.

### `LinkageProof`

| Attribute | Type | Description |
|-----------|------|-------------|
| `master_pubkey` | `str` | Lowercase hex x-only master public key (64 chars) |
| `child_pubkey` | `str` | Lowercase hex x-only child public key (64 chars) |
| `attestation` | `str` | The signed attestation string |
| `signature` | `str` | Lowercase hex BIP-340 Schnorr signature (128 chars) |
| `purpose` | `str \| None` | Purpose string (full proofs only) |
| `index` | `int \| None` | Derivation index (full proofs only) |

`LinkageProof` is frozen (immutable).

### `proof_to_dict(proof) -> dict`

Serialise to the camelCase wire format exchanged with the TypeScript implementation.

### `proof_from_dict(d: dict) -> LinkageProof`

Deserialise from the camelCase wire format.

### `to_unsigned_event(proof, created_at=None) -> UnsignedEvent`

Wrap a `LinkageProof` as an unsigned NIP-78 (Kind 30078) Nostr event. `created_at`
defaults to the current Unix time; pass it explicitly for deterministic output.
Raises `NsecTreeError` if the proof is structurally malformed.

### `from_event(event) -> LinkageProof`

Extract a `LinkageProof` from a NIP-78 event — accepts an `UnsignedEvent` or a mapping
with `pubkey` and `tags`. Raises `NsecTreeError` on missing, duplicate, or malformed
tags. Pass the result to `verify_proof`.

### `UnsignedEvent`

Frozen dataclass whose fields are the Nostr event JSON keys — `kind`, `pubkey`,
`created_at`, `tags`, `content` — so `dataclasses.asdict(ev)` is a ready-to-sign event.

### `NSEC_TREE_EVENT_KIND` / `NSEC_TREE_D_PREFIX`

The NIP-78 kind (`30078`) and the `d`-tag namespace prefix (`nsec-tree:`).

### `encoding` module

| Function | Description |
|----------|-------------|
| `encode_nsec(privkey: bytes) -> str` | Raw bytes → bech32 nsec |
| `decode_nsec(nsec: str) -> bytes` | bech32 nsec → raw bytes |
| `encode_npub(pubkey: bytes) -> str` | Raw bytes → bech32 npub |
| `decode_npub(npub: str) -> bytes` | bech32 npub → raw bytes |

---

## Conformance

nsec-tree-py is verified against the **full frozen vector suite**
([PROTOCOL.md §6.1–6.6](https://github.com/forgesworn/nsec-tree/blob/main/PROTOCOL.md#6-test-vectors)),
covering both the nsec path (§6.1–6.3) and the mnemonic path (§6.4–6.6).

The canonical test-vector inputs (32 bytes of `0x01`):

```
nsec_bytes   = 0101...01  (32 bytes)

tree root (nsec path, §1.2):
  tree_root   = 8d2db9ce9548534e7ae924d05e311355e3a12744214c88e65b39fa2bf2df6d6f
  master_pub  = 8c03e047ae60c01e942a8337e71d17e3517fcc63ee6ceff8173bbd23fabe649d
  master_npub = npub13sp7q3awvrqpa9p2svm7w8ghudghlnrraekwl7qh8w7j8747vjwskvzy2u

vector 1 — purpose "social", index 0:
  child_priv  = 98e98b476eab3c2bcb5020e4a679a41b74eebfb30a07944c4361c906501265e7
  child_pub   = cdc4cd2a01ba1b8afd3299b66c38d13043a19acb687c334f0527cffaf464b372
  child_nsec  = nsec1nr5ck3mw4v7zhj6syrj2v7dyrd6wa0anpgregnzrv8ysv5qjvhnsafv7mx
  child_npub  = npub1ehzv62sphgdc4lfjnxmxcwx3xpp6rxktdp7rxnc9yl8l4arykdeqyfhrxy

vector 2 — purpose "commerce", index 0:
  child_priv  = fc62a2ec7f91970c485f9d7453268d1a6a07273ee829cf44c87685f78758f04f
  child_pub   = 8441f7e2a73fea0742ccd12858bd5b95ccae385fbcb2856b7d7177880198a663

vector 3 — purpose "social", index 1:
  child_priv  = 802a2fd31d25517bd2bb9b7196c377e6cc2f32728b916c2c3ea71ca703767917
  child_pub   = aed0bc4ccccdb868156e38cabf3a6acb98f8fa8a4abe0dcc68851d8468a87cd1
```

The protocol vectors run on every commit (`tests/test_vectors.py`, `tests/test_mnemonic.py`).
Separately, a **61-case differential suite** (`tests/test_reference_vectors.py`) asserts
byte-for-byte equality with the TypeScript **v1.5.1** reference across every public
function — derivation, personas, hierarchy, linkage proofs, and NIP-78 events — so parity
is proven, not assumed.

---

## Status & security

nsec-tree-py is `1.0.0`. It is:

- **Conformance-tested** against the frozen `PROTOCOL.md` vectors (§6.1–6.6) on every commit; and
- **Interop-verified** — its linkage proofs *and* NIP-78 event tags are cross-checked against the TypeScript `nsec-tree` (@noble) in both directions, with genuine reference outputs frozen into the test suite.

It has **not** had an independent security audit. Review it yourself before trusting it with high-value keys. Two honest limits:

- **Zeroisation is best-effort.** CPython cannot scrub immutable `bytes`/`str` in place; `zeroise` and `destroy` drop references but cannot guarantee the old bytes leave memory. Prefer short-lived secrets; do not rely on wiping. The mnemonic path additionally cannot scrub BIP-39/BIP-32 intermediate material (seed bytes) for the same reason.

Report anything you find via [issues](https://github.com/forgesworn/nsec-tree-py/issues).

---

## Value-for-value

MIT-licensed. If nsec-tree-py saves you time, consider a tip:

- ⚡ thedonkey@strike.me · https://strike.me/thedonkey
- https://ko-fi.com/brays
- https://geyser.fund/project/forgesworn

---

## Licence

MIT — see [LICENSE](LICENSE). Copyright © TheCryptoDonkey.

---

## Part of the ForgeSworn toolkit

nsec-tree-py is the Python port of [`forgesworn/nsec-tree`](https://github.com/forgesworn/nsec-tree),
the canonical TypeScript implementation of the nsec-tree protocol. A Rust implementation
exists too; all three produce identical keys for the same inputs.

For LLM and coding-agent consumers, a condensed machine-readable summary lives at
[`llms.txt`](llms.txt).
