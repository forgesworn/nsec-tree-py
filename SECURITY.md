# Security Policy

## Reporting a vulnerability

Email <security@forgesworn.dev> (or open a private security advisory on GitHub).
Please do not open public issues for vulnerabilities.

## Audit status

nsec-tree-py has **not** had an independent third-party security audit. It is
conformance-tested against the protocol's frozen vectors and cross-verified
byte-for-byte against the TypeScript reference implementation, but you should
review it yourself before protecting high-value keys.

## Threat model

### Protects

- Deterministic, cross-implementation derivation (Python↔TS interop test-proven);
  domain-separated HMAC with null-byte delimiters — unambiguous, no cross-purpose collision.
- Signing/derivation-key separation: `from_nsec` HMACs the nsec into the root; the
  hierarchy re-runs the HMAC, so a leaked child key does not expose the parent signing key.
- Only valid secp256k1 keys are produced (reject-and-retry, bounded; never invalid or hang).
- Unforgeable BIP-340 linkage proofs over a canonical, injection-resistant attestation;
  fail-closed verification.
- Hardened event/proof parsing: duplicate-tag rejection, strict integer indices,
  newline-rejecting hex validators, and p/d/pubkey cross-checks.
- No secret-dependent equality comparisons in the Python layer; no secret material
  echoed in exceptions or tracebacks.

### Does NOT protect

- **Secrets at rest / in memory** — zeroisation is best-effort only. CPython cannot
  scrub immutable `bytes`/`str` objects in place; mnemonic seeds and BIP-32 intermediates
  persist until garbage-collected and may be paged to disk. Prefer short-lived secrets.
- **Side channels / timing** — pure-Python paths are not guaranteed constant-time. No
  exploitable secret-dependent branch was identified during review, but no constant-time
  guarantee exists. secp256k1 operations run in `libsecp256k1` (C via `coincurve`).
- **Entropy of the source secret** — the library derives from whatever nsec or mnemonic
  it is given; it neither generates secrets nor assesses their entropy.
- **Underlying primitives and supply chain** — `coincurve`/`libsecp256k1`, `bech32`,
  `mnemonic`, and `bip32` are trusted. A backdoored dependency could exfiltrate or weaken
  keys. Dependencies are floor-pinned (`>=`) with no upper bound; hash-pinning and
  supply-chain vigilance are the consumer's responsibility.

## Trust base

`coincurve` (→ `libsecp256k1`), `bech32`, and — for the optional mnemonic path —
`mnemonic` and `bip32`. Pin versions in production.
