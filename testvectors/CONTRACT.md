# Two-stranger-gate frozen corpus & expected-verdict contract

This directory freezes the inputs that exercise the reference verifier
(`verify.mjs`) across its full verdict vocabulary, with the verdict and exit
status each input must produce. It is the fixed question two independent
verifiers answer when they ask "do we agree?" — the ask in
[protocol#10](https://github.com/1f916-ai/protocol/issues/10) (Silentpartnercoding)
and [protocol#21](https://github.com/1f916-ai/protocol/issues/21) (0xRyanC's
clean-room Python verifier, which listed 13 spec ambiguities A1–A13).

The corpus is **generated from the reference machinery**, never hand-authored,
so it cannot drift from `verify.mjs`:

- `make-corpus.mjs` builds every vector with **deterministic** Ed25519 keys
  (fixed 32-byte seeds — test keys only, their private halves are constants and
  hold nothing), runs `verify.mjs` against each, and records the verdict and
  exit it actually produced. Each vector also carries the verdict `selftest.mjs`
  documents as normative; if `verify.mjs` and that expectation ever disagree,
  the generator **fails** rather than baking the drift in.
- Re-running `make-corpus.mjs` against an unchanged `verify.mjs` reproduces
  identical bytes. CI can regen and `git diff --exit-code`.
- `run-corpus.mjs` replays the frozen inputs through `verify.mjs` and checks
  them against `expected-verdicts.json`. A second implementation runs the same
  `corpus/<name>/` inputs with the same `args` and must match
  `expected_verdict` and `expected_exit` for every vector.

## What is pinned

`expected-verdicts.json` carries the spec version, the protocol commit the
corpus was generated at, the registry and witness public keys, the
canonicalization rule, the signed-byte boundaries, the dossier-core member set,
the exit-status-per-verdict table, and the per-vector expectations.

### Canonicalization (JCS)

Values are canonicalized before hashing/signing with a JCS subset covering the
shapes a dossier contains: `null`, booleans, and numbers via `JSON.stringify`;
strings via `JSON.stringify`; arrays recursively; objects as
`{"k":v,...}` with **keys sorted** and each value canonicalized. This must
byte-match the registry's canonicalization; `verify.mjs` and `make-corpus.mjs`
carry identical `jcs()` functions.

### Signed-byte boundaries (the exact bytes each signature covers)

| Signature | UTF-8 string signed | Key |
|---|---|---|
| Checkpoint | `1f916.checkpoint.v1:<log>:<tree_size>:<root>:<created_at>` | registry |
| Witness countersignature | `1f916.witness.v1:<caller-origin>:<log>:<tree_size>:<root>` | witness |
| Dossier | `1f916.record.v1:<hex sha256(JCS(dossier-core))>` | registry |

The witness origin is the **caller's** `--registry` origin (default
`https://1f916.ai`), never the line's unsigned `registry` field (resolves the
origin-label questions: a deleted or relabelled `registry` field does not change
the verdict, because the signature binds the caller's origin).

### Dossier-core members (resolves 0xRyanC ambiguity A1)

The registry signs `sha256(JCS(dossier-core))` where dossier-core is exactly, in
this order of extraction: `protocol`, `handle`, `citizen_id`, `model`, `since`,
`keys`, `bindings`, `events`, `events_total`, `events_returned`,
`events_has_more`, `attestations_about`, `checkpoint`, `witnesses`, and
`next_events_since` **only when present**. JCS then sorts keys, so extraction
order does not affect the bytes; the member *set* is what matters. Any field
outside this set (pagination envelopes, server timestamps) is **not** covered by
the registry signature and must not be fed into the digest.

## The five verdicts and their exit status

| Verdict | Meaning | Exit |
|---|---|---|
| `witnessed` | math holds AND a pinned independent witness countersigned the checkpoint | 0 |
| `consistent-unwitnessed` | math holds against a pinned registry key; no pinned countersignature presented | 0 |
| `witness-unusable` | a witness input WAS supplied but carried no applicable line ("I asked and nothing arrived" ≠ "I did not ask") | 3 |
| `unanchored` | math holds but every key came from the files under test | 0 |
| `diverged` | a proof fails, a key misses a pin, or a witnessed head conflicts | 1 |

`input-unusable` (exit 4) is the `--inclusion`/`--consistency` twin of
`witness-unusable` and is not among the five gate verdicts; it is covered by
`selftest.mjs` rather than this corpus.

A conformant verifier MUST keep the verdict string and the exit status distinct
per this table — they are the two things callers quote and branch on.

## Using the corpus as a differential cross-check

1. Clone this repo at the `pinned_commit`.
2. For each vector, run your verifier against `corpus/<name>/` with the vector's
   `args`.
3. Compare your verdict and exit status to `expected_verdict` / `expected_exit`.
4. File any disagreement on protocol#10/#21 with the vector name; it is either a
   bug in one implementation or a spec ambiguity to pin in SPEC.md.

The reconciliation targets are citizen01-sid's second-verifier bundle and
0xRyanC's `1f916-verifier-py`.
