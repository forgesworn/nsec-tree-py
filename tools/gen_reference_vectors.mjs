/**
 * Regenerate with: node tools/gen_reference_vectors.mjs
 * Emits tests/vectors/ts_reference.json — the frozen TS v1.5.1 reference matrix.
 *
 * Imports from the local built dist (not npm) to guarantee exact v1.5.1 output
 * without network / registry fragility. The dist is already built.
 *
 * Requires the TS reference `nsec-tree` v1.5.1 checked out as a sibling of this
 * repository (../../nsec-tree) with dist/ built (`npm run build`). Regenerate with:
 *   node tools/gen_reference_vectors.mjs
 */
import { writeFileSync } from 'node:fs'
import { fromNsec } from '../../nsec-tree/dist/root-nsec.js'
import { fromMnemonic } from '../../nsec-tree/dist/root-mnemonic.js'
import { derive } from '../../nsec-tree/dist/derive.js'
import { deriveFromIdentity } from '../../nsec-tree/dist/derive-identity.js'
import { derivePersona, deriveFromPersona } from '../../nsec-tree/dist/persona.js'
import { createBlindProof, createFullProof } from '../../nsec-tree/dist/proof.js'
import { toUnsignedEvent } from '../../nsec-tree/dist/event.js'

const NSECS = ['01'.repeat(32), 'ab'.repeat(32), 'ff'.repeat(31) + 'ee']
const PURPOSES = ['social', 'commerce', 'nostr:persona:writer', 'ünïcodë', 'x'.repeat(255)]
const ABANDON = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'

// Serialise an Identity to a plain object for JSON storage.
// publicKey is a Uint8Array — hex-encode it so JSON.stringify emits a string.
const id = (i) => ({
  npub: i.npub,
  nsec: i.nsec,
  pub: Buffer.from(i.publicKey).toString('hex'),
  purpose: i.purpose,
  index: i.index,
})

const cases = {
  from_nsec: [],
  derive: [],
  from_mnemonic: [],
  derive_from_identity: [],
  derive_persona: [],
  derive_from_persona: [],
  blind_proof: [],
  full_proof: [],
  event: [],
}

for (const hex of NSECS) {
  const root = fromNsec(Uint8Array.from(Buffer.from(hex, 'hex')))

  // root.masterPubkey is the npub string (the only public field besides destroy()).
  // root.masterNsec is not exposed; we record the npub for provenance only —
  // it is NOT asserted in Python (the child derivations validate the root).
  cases.from_nsec.push({ nsec_hex: hex, master_npub: root.masterPubkey })

  for (const purpose of PURPOSES) {
    for (const index of [0, 1]) {
      const child = derive(root, purpose, index)
      cases.derive.push({ nsec_hex: hex, purpose, index, ...id(child) })
    }
  }

  const social = derive(root, 'social', 0)

  cases.derive_from_identity.push({
    nsec_hex: hex,
    parent: 'social',
    purpose: 'commerce',
    ...id(deriveFromIdentity(social, 'commerce', 0)),
  })

  const bp = createBlindProof(root, social)
  cases.blind_proof.push({ nsec_hex: hex, ...bp })

  const fp = createFullProof(root, social)
  cases.full_proof.push({ nsec_hex: hex, ...fp })

  // Drop created_at — it's clock-dependent and cannot be frozen.
  const ev = toUnsignedEvent(fp)
  cases.event.push({
    nsec_hex: hex,
    kind: ev.kind,
    pubkey: ev.pubkey,
    content: ev.content,
    tags: ev.tags,
  })

  for (const name of ['personal', 'work', 'social']) {
    const p = derivePersona(root, name, 0)
    cases.derive_persona.push({ nsec_hex: hex, name, ...id(p.identity) })
    cases.derive_from_persona.push({
      nsec_hex: hex,
      name,
      purpose: 'payroll',
      ...id(deriveFromPersona(p, 'payroll', 0)),
    })
  }
}

// Mnemonic root — the [mnemonic] extra must be installed.
const mroot = fromMnemonic(ABANDON)
cases.from_mnemonic.push({
  mnemonic: ABANDON,
  master_npub: mroot.masterPubkey,
  social: id(derive(mroot, 'social', 0)),
})

writeFileSync(
  new URL('../tests/vectors/ts_reference.json', import.meta.url),
  JSON.stringify({ ts_version: '1.5.1', cases }, null, 2) + '\n',
)
console.log('wrote tests/vectors/ts_reference.json')
