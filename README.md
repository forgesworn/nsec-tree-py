# nsec-tree-py

[![CI](https://github.com/forgesworn/nsec-tree-py/actions/workflows/ci.yml/badge.svg)](https://github.com/forgesworn/nsec-tree-py/actions/workflows/ci.yml)

Deterministic Nostr sub-identity derivation — Python implementation of the
[nsec-tree protocol](https://github.com/forgesworn/nsec-tree/blob/main/PROTOCOL.md)
(NIP-IDENTITY-TREES `v1.1`).

Derives a tree of independent secp256k1 key pairs from a single master nsec.
Each child key is a fully usable Nostr identity (nsec + npub) bound to a
human-readable **purpose** string and a numeric **index**. Children are
cryptographically unlinkable without an explicit linkage proof.

---

## Install

```bash
pip install nsec-tree
```

Requires Python 3.11 or later.

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

print(writer.purpose)  # "nostr:persona:writer"
print(writer.npub)
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

### 7. Zeroisation

Call `zeroise` to wipe an identity's private key bytes when it is no longer
needed:

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

### `TreeRoot`

| Attribute | Type | Description |
|-----------|------|-------------|
| `secret` | `bytes` | 32-byte tree root secret (sensitive) |
| `master_pubkey` | `bytes` | x-only public key (32 bytes) |
| `master_npub` | `str` | bech32 npub of the master identity |

`root.destroy()` overwrites `secret` with null bytes.

### `derive(root, purpose, index=0) -> Identity`

Derive a child identity. Raises `IndexOverflow` if every index up to
`0xFFFFFFFF` fails the curve-order check (astronomically unlikely in practice).

### `derive_persona(root, name, index=0) -> Identity`

Derive the child at purpose `nostr:persona:<name>`.

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

`Identity` is frozen (immutable). Call `zeroise(identity)` to wipe the private
key bytes in place.

### `zeroise(identity: Identity) -> None`

Overwrite `identity.private_key` with null bytes.

### `encoding` module

| Function | Description |
|----------|-------------|
| `encode_nsec(privkey: bytes) -> str` | Raw bytes → bech32 nsec |
| `decode_nsec(nsec: str) -> bytes` | bech32 nsec → raw bytes |
| `encode_npub(pubkey: bytes) -> str` | Raw bytes → bech32 npub |
| `decode_npub(npub: str) -> bytes` | bech32 npub → raw bytes |

---

## Conformance

nsec-tree-py is **byte-identical** to the TypeScript
[`nsec-tree`](https://github.com/forgesworn/nsec-tree) and Rust
`heartwood-core` implementations. All three are verified against the frozen
vectors in [PROTOCOL.md §6](https://github.com/forgesworn/nsec-tree/blob/main/PROTOCOL.md#6-test-vectors).

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

The full vector suite is exercised on every commit via `tests/test_vectors.py`.

---

## Roadmap

The following features are **planned but not yet implemented**:

- **Linkage proofs** (PROTOCOL.md §5) — blind and full Schnorr attestations
  proving master→child ownership
- **Mnemonic-path derivation** (PROTOCOL.md §1.1) — BIP-39/BIP-32 entry point
  (`m/44'/1237'/727'/0'/0'`)

---

## Value-for-value

MIT-licensed. If nsec-tree-py saves you time, consider a tip:

- ⚡ thedonkey@strike.me · https://strike.me/thedonkey
- https://ko-fi.com/brays
- https://geyser.fund/project/forgesworn

---

## Part of the ForgeSworn toolkit

nsec-tree-py is the Python port of [`forgesworn/nsec-tree`](https://github.com/forgesworn/nsec-tree),
the canonical TypeScript implementation of the nsec-tree protocol.
