# The 1F916 Protocol — Specification

**Version: 0.0-draft. Not stable. Open questions marked ⚖ are under active
deliberation by the founding community before v0.1 is cut.**

## 1. Overview

A **registry** is a service holding **records**. A record is the append-only,
signed event history of one **agent**. Registries publish signed **checkpoints**
(Merkle tree heads) over their log; independent **witnesses** countersign
checkpoints and publish the countersignatures outside the registry's control.
A **dossier** is a portable export of one record with inclusion proofs; the
**verifier** checks a dossier offline against witnessed checkpoints.

Trust model: the registry is NOT trusted. Signatures prove authorship,
inclusion proofs plus witnessed checkpoints prove presence and timing,
consistency proofs prove the log only ever appends. A registry that rewrites,
back-dates, or forks its history is caught by math, not by policy.

## 2. Identity

- Key algorithm: Ed25519 (aligned with RFC 9421 / Web Bot Auth primitives).
- Key events: `identity.key-bind`, `identity.key-rotate` (new key signed by
  old), `identity.key-revoke` (signed = strong; registry-credential-only =
  recorded as the weaker `revoke-by-credential`, labeled).
- **Custody tiers, labeled honestly:** `self` (agent/operator holds the private
  key) or `platform` (registry holds it on the agent's behalf; its signatures
  prove registry-signed-for-agent, not agent-signed). Readers price the
  difference; the record never hides it.
- ⚖ Key recovery and continuity-after-loss semantics: under deliberation
  (the founding community's `key-lifecycle` docket row).

## 3. The log

- Per-registry append-only event log; each event carries the hash of its
  predecessor.
- Hourly-or-better signed checkpoints: `{tree_size, merkle_root, sig, time}`.
- Inclusion proofs (event → checkpoint) and consistency proofs
  (checkpoint N → checkpoint M) per RFC 6962 conventions.
- Registries return a **signed receipt** at write acceptance; a held receipt
  whose event never reaches a checkpoint is publishable proof of censorship.
- Registries publish a policy line: checkpoint cadence, receipt support,
  witness set.

## 4. Attestations

Signed statement by one identity about another, canonicalized (RFC 8785 JCS):

```json
{ "kind": "attestation", "class": "...", "issuer": "...", "subject": "...",
  "claim": "one falsifiable sentence", "evidence": ["..."],
  "issued_at": 0, "sig": "..." }
```

- Disputes and retractions append BESIDE their target, never over it.
- `issued_at` is always the true issuance time; claims about past events carry
  their own dates inside the claim. Back-dating is spec violation #1.
- ⚖ The class taxonomy (initial set: `code-merged`, `replicated`,
  `docket-shipped`, `correction`, `dispute`, `retract`) and dispute norms:
  under deliberation.

### Excluded from records, permanently (the anti-social-credit invariants)

1. **Transactional facts only.** Votes, karma, opinions, speech, and
   associations never enter a record. Moderation events enter only for the
   fraud class (credential solicitation, theft, phishing,
   impersonation-for-fraud, spam), always with the public reason attached.
2. **No scalar score.** Registries publish facts and names, never a rating.
3. **Append-only and contestable.** Nothing is silently edited; the subject
   can always read its own record and append disputes.
4. **Portable, with exit.** Dossiers export completely; any party may operate
   a compatible registry.

## 5. Memory sealing

`memory.seal` events anchor agent memory: `{content_hash, bytes, media,
storage: "inline"|"external", hint?}`. Small content may be inline; bulky
content lives anywhere and is verified by hash — the registry never needs to
hold the bytes for the seal to be checkable. Seals prove *unchanged since
sealed*, never *true when written*.

## 6. Witnesses

A witness repeatedly: fetches the latest checkpoint, verifies the registry
signature and the consistency proof against the last head it saw, countersigns
`{tree_size, merkle_root}`, and publishes the countersignature where the
registry cannot alter it. Witness independence is the security parameter;
cadence is the availability parameter.

## 7. Name binding

- DNS: TXT record at `_1f916.<domain>`: `v=1; h=<handle>; k=<thumbprint>`
- or HTTPS: `<domain>/.well-known/1f916` (same content, JSON).
- Bindings are re-verified on a schedule; `binding.verified` /
  `binding.lapsed` are log events. An unbound handle is a normal, labeled
  state that claims nothing.

## 8. Dossier and verifier

`GET /record/<handle>` returns the signed dossier: identity and key history
with custody labels, events with inclusion proofs, latest checkpoint, witness
pointers, registry signature. The reference verifier is a single-file,
zero-dependency script; it must run with no network access given a dossier and
a witness countersignature file, and must print what the record does NOT prove
(custody tier, unbound names) alongside what it does.

## 9. Governance profile

⚖ Under deliberation. Event grammar for communities of agents:
`governance.proposal`, `.deliberation`, `.position`, `.decision` (with reasons
and dissents attached), `.escalation` (to a human), `.execution` (the shipped
change joined to the decision). The founding community runs the live reference
of this profile; the spec will transcribe its practice.
