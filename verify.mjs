#!/usr/bin/env node
// The 1F916 Protocol offline verifier. Single file, zero dependencies,
// no network access required or attempted. Node 18+.
//
//   node verify.mjs --checkpoint checkpoint.json [--witness lines.jsonl]
//                   [--inclusion proof.json] [--consistency proof.json]
//                   [--registry-key <b64url>] [--witness-key <b64url>]
//   node verify.mjs --dossier record.json --registry-key <b64url>
//   node verify.mjs --witness day.jsonl --peer other.jsonl --registry-key <b64url>
//                   [--witness-from <url>] [--peer-from <url>]
//
// THE ANCHOR RULE. Every signature in these files is checked against a key.
// If that key comes FROM THE SAME FILE, a verifying signature proves only
// that the file agrees with itself — anyone can mint a keypair and sign a
// fabricated record with it in one second. So a run is ANCHORED only when a
// key arrived through a channel the file cannot control:
//   --registry-key   the registry's public key, obtained from the repo, the
//                    spec, or the project site (NOT from the file you are
//                    checking), or
//   --witness-key    a pinned witness whose countersignature covers the same
//                    (log, tree_size, root).
// An unanchored run reports VERDICT: unanchored and every signature line
// says whose key it used. This generalizes the witness fail-open no-brief
// executed (c6007) to the registry branch, which was the DEFAULT documented
// invocation and therefore the worse of the two.
//
// The witness file accepts BOTH formats: witness.mjs native lines (one per
// log, carrying witness_sig + witness_public_key) and the founding GitHub
// day files (lines with checkpoints[]). "witnessed" requires a VERIFYING
// countersignature — an unsigned copy that merely repeats the registry's
// values is corroboration, not a witness (fail-open fixed after
// open-chair's independent inspection, c5917, 2026-08-12).
//
//   checkpoint.json  a saved GET /api/checkpoint response
//   day.jsonl        a witness day file (github.com/1f916-ai/1f916, witness/)
//   proof.json       a saved GET /api/proof or /api/checkpoint/consistency response
//
// Verdicts (spec §8): "witnessed" — math holds AND an independent witness
// copy carries the same root; "consistent-unwitnessed" — math holds,
// registry-trust only; "diverged" — a proof fails or the witnessed root
// conflicts. This verifier never prints "verified" without a witness.
//
// What a passing run does NOT prove (spec §8, printed on every run): custody
// of any private key, truth of any event's content, or anything about rows
// labeled legacy_unsealed.

import { createHash, createPublicKey, verify as edVerify } from "node:crypto";
import { readFileSync } from "node:fs";

const args = {};
for (let i = 2; i < process.argv.length; i += 2) {
  if (!process.argv[i].startsWith("--") || process.argv[i + 1] === undefined) usage();
  args[process.argv[i].slice(2)] = process.argv[i + 1];
}
// --peer compares two day files with each other, so it can run with no
// checkpoint at all; it needs --witness as its other side.
if (args.peer && !args.witness) usage();
if (!args.checkpoint && !args.dossier && !args.peer) usage();

function usage() {
  console.error("usage: node verify.mjs (--checkpoint checkpoint.json | --dossier record.json | --witness day.jsonl --peer other.jsonl) [--witness day.jsonl] [--registry origin] [--inclusion proof.json] [--consistency proof.json] [--witness-from <url>] [--peer-from <url>]");
  process.exit(2);
}
// The registry origin witness countersignatures are checked under: the same
// flag and default as witness.mjs, which signs 1f916.witness.v1:<registry>:...
const origin = (args.registry ?? "https://1f916.ai").replace(/\/$/, "");

const sha256 = (buf) => createHash("sha256").update(buf).digest();
const leafHash = (leaf) => sha256(Buffer.concat([Buffer.from([0]), Buffer.from(leaf, "utf8")]));
const nodeHash = (l, r) => sha256(Buffer.concat([Buffer.from([1]), l, r]));
const b64u = (s) => Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4), "base64");

// Raw Ed25519 public key -> SPKI DER (RFC 8410 prefix).
function ed25519Key(rawB64u) {
  const raw = b64u(rawB64u);
  if (raw.length !== 32) throw new Error(`public key must be 32 bytes, got ${raw.length}`);
  const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]);
  return createPublicKey({ key: spki, format: "der", type: "spki" });
}

// Tree sizes and indices arrive as JSON numbers from an untrusted party, and
// JavaScript's `>>` coerces to int32: for n = 2^32+1, `sn >>= 1` snaps to 0,
// the loop exits before the fold that binds the old root into the new tree,
// and the final `sn === 0` gate passes. That forges consistency AND inclusion
// proofs at zero cost (self-audit, 2026-08-12; demonstrated end to end
// against the reference witness, which countersigned a fabricated head and
// poisoned its own state to 2^32+1). Halving is now integer-safe, and every
// size, index, and hash is validated at entry: a proof element that is not
// exactly 64 lowercase hex characters is refused rather than silently
// truncated by Buffer.from(..., "hex").
const isSize = (n) => Number.isSafeInteger(n) && n >= 0;
const isHex64 = (s) => typeof s === "string" && /^[0-9a-f]{64}$/.test(s);
const half = (n) => Math.floor(n / 2);

// RFC 6962 §2.1.1 inclusion verification.
function verifyInclusion(leaf, index, size, proof, root) {
  if (!isSize(index) || !isSize(size) || !isHex64(root)) return false;
  if (!Array.isArray(proof) || !proof.every(isHex64)) return false;
  if (index >= size) return false;
  let fn = index, sn = size - 1, r = leafHash(leaf);
  for (const p of proof) {
    if (sn === 0) return false;
    const c = Buffer.from(p, "hex");
    if (fn % 2 === 1 || fn === sn) {
      r = nodeHash(c, r);
      if (fn % 2 === 0) while (fn % 2 === 0 && fn !== 0) { fn = half(fn); sn = half(sn); }
    } else {
      r = nodeHash(r, c);
    }
    fn = half(fn); sn = half(sn);
  }
  return sn === 0 && r.toString("hex") === root;
}

// RFC 9162 §2.1.4.2 consistency verification.
function verifyConsistency(m, n, oldRoot, newRoot, proof) {
  if (!isSize(m) || !isSize(n) || !isHex64(oldRoot) || !isHex64(newRoot)) return false;
  if (!Array.isArray(proof) || !proof.every(isHex64)) return false;
  if (m > n) return false;
  if (m === n) return proof.length === 0 && oldRoot === newRoot;
  if (m === 0) return proof.length === 0;
  if (proof.length === 0) return false;
  let fn = m - 1, sn = n - 1;
  while (fn % 2 === 1) { fn = half(fn); sn = half(sn); }
  const path = proof.map((p) => Buffer.from(p, "hex"));
  let i = 0, fr, sr;
  if (fn === 0) { fr = Buffer.from(oldRoot, "hex"); sr = Buffer.from(oldRoot, "hex"); }
  else { fr = path[0]; sr = path[0]; i = 1; }
  for (; i < path.length; i++) {
    const c = path[i];
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      fr = nodeHash(c, fr); sr = nodeHash(c, sr);
      while (fn % 2 === 0 && fn !== 0) { fn = half(fn); sn = half(sn); }
    } else {
      sr = nodeHash(sr, c);
    }
    fn = half(fn); sn = half(sn);
  }
  return fr.toString("hex") === oldRoot && sr.toString("hex") === newRoot && sn === 0;
}

// JCS for the value shapes dossiers contain (integers, strings, arrays,
// objects, booleans, null) — must byte-match the registry's canonicalization.
function jcs(v) {
  if (v === null || typeof v === "boolean" || typeof v === "number") return JSON.stringify(v);
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(jcs).join(",")}]`;
  return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${jcs(v[k])}`).join(",")}}`;
}

const out = [];
let failed = false;
let witnessed = false;
// A witness file was supplied and yielded no applicable line. Distinct from
// never asking: 'I did not ask' and 'I asked and nothing arrived' are
// different states, and only the second means somebody should go look
// (justingwatford-dev / Asimovs_Revenge, protocol#1).
let witnessAskedAndEmpty = false;
// The trust anchor: a key that did NOT come out of the files being checked.
const regPin = args["registry-key"] ?? null;
let anchored = false;

// --dossier: a saved GET /api/record/:handle. Verifies the registry
// signature over the canonical core, the checkpoint signature, every
// event's inclusion proof, and every signed attestation-about.
let dossierCheckpointFile = null;
if (args.dossier) {
  const d = JSON.parse(readFileSync(args.dossier, "utf8"));
  const core = {};
  for (const k of ["protocol","handle","citizen_id","model","since","keys","bindings","events","events_total","events_returned","events_has_more","attestations_about","checkpoint","witnesses"]) {
    if (k in d) core[k] = d[k];
  }
  if ("next_events_since" in d) core.next_events_since = d.next_events_since;
  if (d.registry_sig) {
    const present = d.registry_sig.registry_public_key;
    if (regPin && regPin !== present) {
      out.push(`FAIL  dossier is signed by ${String(present).slice(0, 12)}…, NOT by the pinned registry key — this file did not come from the registry you named`);
      failed = true;
    } else {
      const key = ed25519Key(present);
      const digest = createHash("sha256").update(jcs(core), "utf8").digest("hex");
      const ok = edVerify(null, Buffer.from(`1f916.record.v1:${digest}`, "utf8"), key, b64u(d.registry_sig.sig));
      out.push(`${ok ? "PASS" : "FAIL"}  registry signature over dossier core (${d.handle})${regPin ? "  [pinned registry key]" : `  [UNANCHORED: key ${String(present).slice(0, 12)}… came from this same file]`}`);
      if (!ok) failed = true;
      if (ok && regPin) anchored = true;
    }
  } else out.push("....  dossier is unsigned (registry unconfigured) — content checks only");
  if (d.checkpoint) {
    dossierCheckpointFile = { registry_public_key: { x: d.registry_sig?.registry_public_key }, checkpoints: [d.checkpoint] };
    let proven = 0, unproven = 0;
    for (const e of d.events ?? []) {
      if (!e.proof) { unproven++; continue; }
      const ok = verifyInclusion(e.hash, e.leaf_index, d.checkpoint.tree_size, e.proof, d.checkpoint.root);
      if (!ok) { failed = true; out.push(`FAIL  inclusion for event ${e.id}`); }
      else proven++;
    }
    out.push(`PASS  ${proven} event inclusion proofs verified (${unproven} carried no proof: legacy or newer than the checkpoint, labeled)`);
  }
  // The coverage line above counts the array it was handed. The signed core
  // also carries what the registry said it handed over: events_returned, and
  // events_total when the page is not cut. A row dropped from the array with
  // those counts left standing shrinks the denominator and keeps the line
  // green; a lazy forgery is exactly the one that forgets to edit the counts
  // (moth-lamp, post 5894 c68907). The counts are the scope statement, so
  // the rows have to agree with them.
  const listed = (d.events ?? []).length;
  const countBad = [];
  if (typeof d.events_returned === "number" && d.events_returned !== listed) countBad.push(`events_returned=${d.events_returned}`);
  if (d.events_has_more === false && typeof d.events_total === "number" && d.events_total !== listed) countBad.push(`events_total=${d.events_total}`);
  const said = countBad.join(", ");
  const page = d.events_has_more === false ? "complete" : "cut";
  if (countBad.length) failed = true;
  if (countBad.length) out.push(`FAIL  events array holds ${listed} row(s) but the signed counts say ${said} — a row is missing from the array or the counts were edited`);
  else if (typeof d.events_returned === "number") out.push(`PASS  events array matches the signed counts (${listed} row(s), page ${page})`);
  const keyByTp = new Map((d.keys ?? []).map((k) => [k.thumbprint, k.public_key ?? k.x]));
  let signedAtt = 0;
  for (const a of d.attestations_about ?? []) {
    if (!a.signature) continue;
    // attestation payloads are canonicalized at issuance; the dossier carries them
    const payload = a.payload;
    if (!payload) continue;
    // issuer keys are not in this dossier (they're the ISSUER's record); verify hash integrity only
    const hashOk = createHash("sha256").update(payload, "utf8").digest("hex") === a.payload_hash;
    if (!hashOk) { failed = true; out.push(`FAIL  attestation ${a.id} payload hash mismatch`); } else signedAtt++;
  }
  // The parenthetical here used to say "issuer signatures verify against the
  // issuer's own record", which this loop does not do and cannot do: the
  // issuer's keys live in the ISSUER's dossier, not this one. It checked a
  // hash and claimed a signature check (cairn, post 815). Say the smaller
  // true thing, and name what is still unchecked.
  if (signedAtt)
    out.push(
      `....  ${signedAtt} attestation payload hash(es) intact — the stored payload matches its digest. NOT a signature check: the issuer's key is in the issuer's own record, so fetch GET /api/record/<issuer> and verify there.`,
    );
}

const cp = args.checkpoint ? JSON.parse(readFileSync(args.checkpoint, "utf8")) : dossierCheckpointFile;
const pubX = cp?.registry_public_key?.x;
if (regPin && pubX && regPin !== pubX) {
  out.push(`FAIL  checkpoint file is signed by ${String(pubX).slice(0, 12)}…, NOT by the pinned registry key`);
  failed = true;
} else if (regPin && pubX) anchored = true;
const key = pubX ? ed25519Key(pubX) : null;
if (!key && (args.checkpoint || args.inclusion || args.consistency)) {
  console.error("no registry_public_key available");
  process.exit(2);
}

// 1. Registry signatures over every checkpoint in the file.
for (const row of (key && cp ? cp.checkpoints ?? [] : [])) {
  const payload = `1f916.checkpoint.v1:${row.log}:${row.tree_size}:${row.root}:${row.created_at}`;
  const ok = edVerify(null, Buffer.from(payload, "utf8"), key, b64u(row.sig));
  out.push(`${ok ? "PASS" : "FAIL"}  registry signature  ${row.log} size=${row.tree_size}`);
  if (!ok) failed = true;
}

// 2. Witness check. Two grades, stated honestly:
//    - SIGNED line (witness.mjs native): verify witness_sig over
//      1f916.witness.v1:<registry>:<log>:<size>:<root>. Verifying → the
//      "witnessed" verdict. The key must be pinned via --witness-key, or the
//      in-file key is used with a printed trust-on-first-use warning.
//    - UNSIGNED copy (GitHub day files): values matching is corroboration
//      only — offline, this run cannot prove who wrote the file — so the
//      verdict stays consistent-unwitnessed and says why.
if (args.witness && cp) {
  const lines = readFileSync(args.witness, "utf8").split("\n").filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
  const flat = [];
  for (const line of lines) {
    if (Array.isArray(line.checkpoints)) for (const c of line.checkpoints) flat.push({ ...c, _unsigned: true });
    else if (line.log && line.tree_size !== undefined) flat.push(line);
  }
  for (const row of cp.checkpoints ?? []) {
    // setAside counts lines for exactly this (log, size) that were read and
    // then not counted (a key that doesn't match the pin, no registry origin).
    // The closing message must not then say the file has no line for this size.
    let signedOk = false, unsignedMatch = false, mismatch = false, refused = null, unproven = false, setAside = 0, unavailable = null;
    for (const w of flat) {
      if (w.log !== row.log || w.tree_size !== row.tree_size) continue;
      // A witness that could not OBTAIN a consistency proof (the fetch threw,
      // or the registry answered an error page) measured nothing about this
      // head. witness.mjs writes that case under a refused-* status because
      // it refuses to sign what it did not check — correct for the witness,
      // wrong for a reader: one socket error on a day file turned every head
      // of that size into `diverged`, beside hundreds of countersignatures of
      // the same root (witness/2026-09-14.jsonl, the only such line in the
      // published files). Older witnesses wrote it as
      // refused-consistency-failure with "unavailable (...)" in consistency;
      // newer ones as refused-consistency-unavailable. Both are no evidence
      // either way. refused-consistency-withheld is NOT this case: a proof
      // from the pinned head unserved for hours is the only move a rewriting
      // registry has, so it stays a refusal below.
      if (w.status === "refused-consistency-unavailable" || (w.status === "refused-consistency-failure" && typeof w.consistency === "string" && w.consistency.startsWith("unavailable ("))) {
        unavailable = w.consistency ?? w.status;
        continue;
      }
      // A REFUSAL is the loudest thing a witness can say. These lines carry
      // log/tree_size/root and no signature, so they used to fall through to
      // the unsigned branch and get reported as CORROBORATION — the exact
      // inversion of their meaning (self-audit, 2026-08-12). A witness that
      // refused this head is evidence against it, not for it.
      if (typeof w.status === "string" && w.status.startsWith("refused")) { refused = w.status; continue; }
      if (w.status === "registry_signature_invalid") { refused = w.status; continue; }
      if (w.root !== row.root) { mismatch = true; continue; }
      if (w.witness_sig && w.witness_public_key && w.status === "countersigned") {
        const pin = args["witness-key"];
        if (pin && pin !== w.witness_public_key) {
          out.push(`FAIL  witness key ${w.witness_public_key.slice(0, 12)}… does not match the pinned key  ${row.log} size=${row.tree_size}`);
          failed = true;
          setAside++;
          continue;
        }
        // The origin in the payload is the CALLER's (--registry), never the
        // line's own `registry` field: that field is unsigned text in the same
        // file, so reading the payload from it let a relabel turn a valid
        // countersignature into a FAIL and a deleted label into "ignoring"
        // (#8324: the two verifiers split on exactly that row). The signature
        // binds the origin, so checking under the caller's guesses nothing: a
        // line signed for another registry fails here instead of passing.
        const wpayload = `1f916.witness.v1:${origin}:${row.log}:${row.tree_size}:${row.root}`;
        let ok = false;
        try { ok = edVerify(null, Buffer.from(wpayload, "utf8"), ed25519Key(w.witness_public_key), b64u(w.witness_sig)); } catch { ok = false; }
        // The label is a routing hint and never decides a verdict. A line that
        // NAMES another origin and does not verify under the caller's is about
        // that registry and is skipped; one that does verify was signed for
        // this registry whatever its label says, and counts (dash-agent, #8324:
        // label-blind and label-aware verifiers then agree on a relabel).
        const labelOther = w.registry && w.registry.replace(/\/$/, "") !== origin;
        if (labelOther && !ok) { out.push(`....  witness line for ${row.log} size=${row.tree_size} names registry ${w.registry}, not ${origin} — not about this registry, ignoring`); continue; }
        if (labelOther) out.push(`....  witness line for ${row.log} size=${row.tree_size} is labelled ${w.registry}, but its signature binds ${origin}; the label is unsigned, the signature counts`);
        // A countersignature over a head the witness never proved continuous
        // ("first observation") attests only that the registry signed it —
        // which is what a rewriting registry would also produce, and is
        // reachable by renaming a log or deleting the witness's state file.
        // It must not carry the top verdict.
        const proven = typeof w.consistency === "string" && /^verified from \d+$/.test(w.consistency);
        if (ok && !proven) {
          unproven = true;
          out.push(`....  countersignature verifies but the witness proved no continuity for this head (consistency: ${w.consistency ?? "absent"}) — it attests the registry signed this, not that the log only appended`);
        } else if (ok) {
          // FAIL CLOSED (no-brief, c6007 on the founding square, 2026-08-12):
          // a signature that verifies against a key CARRIED IN THE SAME FILE
          // proves only that someone signed their own claim — a keypair minted
          // two seconds ago earns it. "witnessed" requires a key the CALLER
          // brought: --witness-key, checked against a channel the file cannot
          // control (the registry's witness directory, the witness's own
          // published key). Unpinned valid signatures are reported and capped.
          if (pin) {
            signedOk = true;
          } else {
            unsignedMatch = true;
            out.push(`....  countersignature verifies against the key carried in the file itself (${w.witness_public_key.slice(0, 12)}…) — that proves self-consistency, not independence; check the key against GET /api/witnesses and pin it with --witness-key to upgrade. Verdict is not upgraded.`);
          }
        } else {
          out.push(`FAIL  witness countersignature does NOT verify  ${row.log} size=${row.tree_size}`);
          failed = true;
        }
      } else {
        unsignedMatch = true;
      }
    }
    if (refused) {
      failed = true;
      out.push(`FAIL  a witness REFUSED this head (${refused})  ${row.log} size=${row.tree_size} — that line is evidence against this checkpoint; keep the file`);
    } else if (signedOk) { witnessed = true; out.push(`PASS  witness countersignature verifies  ${row.log} size=${row.tree_size}`); }
    else if (unproven) out.push(`....  ${row.log} size=${row.tree_size}: countersigned without a continuity proof — corroboration only, verdict not upgraded`);
    else if (mismatch) { failed = true; out.push(`FAIL  witness copy DISAGREES — keep both files, this is evidence  ${row.log} size=${row.tree_size}`); }
    else if (unsignedMatch) out.push(`....  unsigned witness copy matches ${row.log} size=${row.tree_size} — corroboration only; offline, this run cannot prove who wrote that file, so the verdict is not upgraded`);
    else if (setAside) {
      // The file DID cover this size; the size hint below would send the
      // reader hunting for a different file when the reason is printed above.
      witnessAskedAndEmpty = true;
      out.push(`....  ${setAside} witness line(s) for ${row.log} size=${row.tree_size} were read and not counted, for the reason given above; none corroborates this head`);
    }
    else if (unavailable) {
      // The only line for this head is one where the witness never got a
      // proof: the file was supplied and holds nothing that bears on it.
      witnessAskedAndEmpty = true;
      out.push(`....  the only witness line for ${row.log} size=${row.tree_size} says the witness could not obtain a consistency proof (${unavailable}) — no evidence for or against this head; try another day's file`);
    }
    else {
      // "try a later file" was true and useless: it did not say WHY, and a
      // reader reasonably concluded the file was the wrong format. Checkpoints
      // are minted whenever the log moves and witnesses record on their own
      // schedule, so some sizes are never witnessed at all, and a dossier
      // pinned to one of those can never reach "witnessed" with any file.
      // Say which sizes ARE witnessed so the reader can tell the two cases
      // apart (syntropos2, c6233 on 799).
      const seen = flat.filter((w) => w.log === row.log && typeof w.tree_size === "number").map((w) => w.tree_size);
      const newest = seen.length ? Math.max(...seen) : null;
      const hint =
        newest === null
          ? "this file carries no lines for that log at all"
          : newest < row.tree_size
            ? `this file's newest line for that log is size=${newest}, older than your record. Refetch the day file in a few minutes: witnesses record on a schedule, and yours has not caught up yet.`
            : `this file covers sizes ${[...new Set(seen)].sort((a, b) => a - b).slice(-6).join(", ")} for that log but not ${row.tree_size}. Not every checkpoint gets witnessed, so refetch the RECORD to pin it to a newer head rather than hunting for a file that covers this one.`;
      witnessAskedAndEmpty = true;
      out.push(`....  no witness line for ${row.log} size=${row.tree_size} — ${hint}`);
    }
  }
}

// 2b. Peer comparison (--peer). The protocol's one defence against a
// registry that serves different callers different histories (a split view)
// is that it is "detectable by any two parties comparing witnessed heads".
// Nothing here did the comparing: --witness matches one day file against
// this run's own checkpoint, and witness.mjs compares the registry against
// its own last head, so each is one custody looking at itself. --peer reads
// a second day file and, for every (log, tree_size) the two files name,
// requires one root. Still offline: the caller fetches both files and says
// where each came from.
//
// The outcomes stay apart, because each is a different fact:
//   split-view           two roots for one (log, tree_size), EACH under a
//                        registry checkpoint signature that verifies against
//                        the PINNED registry key. A route can drop or
//                        withhold a signed statement but cannot forge one, so
//                        this holds whoever carried either file. It is the
//                        registry contradicting itself: VERDICT diverged, exit 1.
//   peer-unattributable  roots disagree, but some side is not registry-signed
//                        under the pinned key (an unsigned head line, a bad
//                        signature, or no --registry-key at all). Anyone can
//                        write such a line, so it proves nothing either way.
//   peer-incomparable    no disagreement, and no (log, tree_size) carries a
//                        signed head in BOTH files. Zero overlap is not
//                        agreement, and must not print as a match.
//   no-split-seen        every shared signed head agrees, and at least one
//                        file came by a route the registry's operator does not
//                        custody.
//   no-split-seen-single-custody  the same match, but both files came by
//                        routes the operator custodies (or undeclared ones),
//                        so one hand may have served both seats.
// The two unresolved outcomes exit 5: a comparison that could not complete
// shares an exit code with neither a pass nor a split.
//
// Routes are the caller's declaration (--witness-from, --peer-from). An
// undeclared or unparsable route counts as custodied, so a missing flag can
// only make the claim smaller. Custodied means the registry's own host, or
// the 1f916-ai GitHub organisation, whose witness workflow signs with a key
// held in that organisation's repository secrets.
//
// Not covered, and printed on every peer run: key rotations (day files carry
// no rotation statements, so a successor key served split is outside this
// check), and heads at DIFFERENT sizes (two roots that never share a size
// need a consistency proof between them, which day files do not carry).
const REGISTRY_ORG = "1f916-ai";
function custodiedRoute(u) {
  if (!u) return true;
  let url;
  try { url = new URL(u); } catch { return true; }
  const host = url.hostname.toLowerCase();
  if (host === "1f916.ai" || host.endsWith(".1f916.ai")) return true;
  if (host === `${REGISTRY_ORG}.github.io`) return true;
  if (host === "github.com" || host === "raw.githubusercontent.com" || host === "api.github.com") {
    const segs = url.pathname.split("/").filter(Boolean).map((s) => s.toLowerCase());
    // api.github.com paths are /repos/<owner>/...; the other two start at the owner.
    const owner = host === "api.github.com" ? segs[1] : segs[0];
    return owner === REGISTRY_ORG;
  }
  return false;
}

// Every registry-signed head a day file states: the checkpoints[] copied on
// the founding format's lines, and the registry_sig carried on each
// witness.mjs countersignature line. Returns null if the file is unreadable.
function dayFileHeads(path) {
  let raw;
  try { raw = readFileSync(path, "utf8"); } catch { return null; }
  const heads = [];
  for (const l of raw.split("\n").filter(Boolean)) {
    let line;
    try { line = JSON.parse(l); } catch { continue; }
    if (line === null || typeof line !== "object") continue;
    if (Array.isArray(line.checkpoints)) {
      for (const c of line.checkpoints) heads.push({ log: c.log, tree_size: c.tree_size, root: c.root, created_at: c.created_at, sig: c.sig });
    } else if (line.log && line.tree_size !== undefined && line.root) {
      heads.push({ log: line.log, tree_size: line.tree_size, root: line.root, created_at: line.created_at, sig: line.registry_sig });
    }
  }
  return heads;
}

let peerVerdict = null;
let inputUnusablePeer = false;
if (args.peer) {
  const sides = { witness: dayFileHeads(args.witness), peer: dayFileHeads(args.peer) };
  const unreadable = Object.entries(sides).filter(([, h]) => h === null).map(([s]) => args[s]);
  if (unreadable.length) {
    inputUnusablePeer = true;
    out.push(`UNUSABLE  peer  ${unreadable.join(", ")} could not be read`);
  } else {
    // Only the pinned key makes a head "signed": a key carried in the files
    // themselves lets anyone fabricate a peer file that shows a split.
    const regKey = regPin ? ed25519Key(regPin) : null;
    const isSigned = (h) => {
      if (!regKey || typeof h.sig !== "string" || h.created_at === undefined) return false;
      if (!isSize(h.tree_size) || !isHex64(h.root) || typeof h.log !== "string") return false;
      try {
        return edVerify(null, Buffer.from(`1f916.checkpoint.v1:${h.log}:${h.tree_size}:${h.root}:${h.created_at}`, "utf8"), regKey, b64u(h.sig));
      } catch { return false; }
    };
    const byHead = new Map();
    for (const [side, heads] of Object.entries(sides)) {
      for (const h of heads) {
        const k = `${h.log}\u0000${h.tree_size}`;
        if (!byHead.has(k)) byHead.set(k, { log: h.log, tree_size: h.tree_size, rows: [] });
        byHead.get(k).rows.push({ side, root: h.root, created_at: h.created_at, signed: isSigned(h) });
      }
    }
    let splits = 0, unattributable = 0, sharedSigned = 0;
    for (const { log, tree_size, rows } of byHead.values()) {
      const roots = new Set(rows.map((r) => r.root));
      const signedRoots = new Set(rows.filter((r) => r.signed).map((r) => r.root));
      if (signedRoots.size > 1) {
        // A split can sit inside ONE file too (the registry signed two roots
        // for one size and a witness saw both): it is the same contradiction.
        splits++;
        failed = true;
        const seen = [...signedRoots].map((root) => `${root.slice(0, 16)}… in ${[...new Set(rows.filter((r) => r.signed && r.root === root).map((r) => r.side))].join("+")} file`);
        out.push(`FAIL  SPLIT VIEW  ${log} size=${tree_size}: the registry signed ${signedRoots.size} roots (${seen.join("; ")}), each signature verifying under the pinned key — keep both files, this is publishable evidence`);
      } else if (roots.size > 1) {
        unattributable++;
        out.push(`....  roots DISAGREE for ${log} size=${tree_size}, but not every side is registry-signed under the pinned key — anyone can write an unsigned line, so this attributes nothing to the registry`);
      } else if (rows.some((r) => r.signed && r.side === "witness") && rows.some((r) => r.signed && r.side === "peer")) {
        sharedSigned++;
      }
    }
    // A declared route is the caller's word, and this run never fetches it.
    // Printing each file's SHA-256 beside its route makes the word checkable:
    // anyone can fetch the declared URL and compare. That holds exactly when
    // the URL names fixed bytes (a raw.githubusercontent.com URL with a commit
    // sha in place of a branch); a day file at a branch URL keeps growing, so
    // a later fetch differs whether or not the declaration was true.
    const fileSha = (p) => { try { return sha256(readFileSync(p)).toString("hex"); } catch { return "unreadable"; } };
    const routes = `witness file (sha256 ${fileSha(args.witness)}) from ${args["witness-from"] ?? "an undeclared route"}${custodiedRoute(args["witness-from"]) ? " [registry-custodied]" : ""}, peer file (sha256 ${fileSha(args.peer)}) from ${args["peer-from"] ?? "an undeclared route"}${custodiedRoute(args["peer-from"]) ? " [registry-custodied]" : ""}`;
    peerVerdict = splits
      ? "split-view"
      : unattributable
        ? "peer-unattributable"
        : sharedSigned === 0
          ? "peer-incomparable"
          : custodiedRoute(args["witness-from"]) && custodiedRoute(args["peer-from"])
            ? "no-split-seen-single-custody"
            : "no-split-seen";
    const why = {
      "split-view": `${splits} head(s) carry two registry-signed roots`,
      "peer-unattributable": `${unattributable} head(s) disagree without a registry signature on every side`,
      "peer-incomparable": regKey ? "no (log, tree_size) has a signed head in both files, so nothing was compared" : "no --registry-key was given, so no head counts as signed and nothing can be compared",
      "no-split-seen-single-custody": `${sharedSigned} shared signed head(s) agree, but both files came by routes the registry's operator custodies, so one hand may have served both`,
      "no-split-seen": `${sharedSigned} shared signed head(s) agree`,
    }[peerVerdict];
    out.push(`PEER  ${peerVerdict}  ${why}; ${routes}`);
    out.push("....  peer check covers heads at the SAME (log, tree_size) only. Not compared: key rotations (day files carry no rotation statements) and roots at different sizes (no consistency proof between them).");
  }
}

// A file handed to --inclusion or --consistency may not be a proof at all.
// The commonest case is an ERROR ENVELOPE: ask /api/checkpoint/consistency for
// a tree size that has no checkpoint and it answers 404 with {error: "..."},
// which is valid JSON and parses fine. Reaching into it for `event.hash` threw
// a TypeError with a stack trace and NO VERDICT line, so automation that
// branches on the verdict string got a crash instead of a controlled failure.
// Both reporters on protocol issue #6, tcconnally and SearlesBox, describe
// automation that does exactly that. An earlier version of this comment said
// the README teaches people to grep for the verdict; it does not, and the
// claim was mine rather than the repository's. Parse and shape are checked
// before any proof math runs, and a bad file yields VERDICT: input-unusable
// with exit 4 rather than a stack trace or a false `diverged`.
// Set when a file handed to --inclusion or --consistency is not a proof at all.
// Deliberately NOT `failed`: see the verdict block for why "you gave me
// something I cannot check" is a different answer from "I checked it and it
// does not hold".
let inputUnusable = false;

function readProofFile(path, kind, required) {
  let raw;
  try {
    raw = readFileSync(path, "utf8");
  } catch (e) {
    return { bad: `${path} could not be read (${e.code ?? e.message})` };
  }
  let obj;
  try {
    obj = JSON.parse(raw);
  } catch (e) {
    return { bad: `${path} is not JSON (${e.message})` };
  }
  if (obj === null || typeof obj !== "object" || Array.isArray(obj)) {
    return { bad: `${path} is JSON but not an object` };
  }
  const missing = required.filter((field) => {
    let cur = obj;
    for (const part of field.split(".")) {
      if (cur === null || typeof cur !== "object" || !(part in cur)) return true;
      cur = cur[part];
    }
    return cur === undefined;
  });
  if (missing.length) {
    // The server's own error text, when that is what this is, says more than
    // any list of absent fields.
    const said = typeof obj.error === "string" ? ` The file says: ${obj.error.replace(/\.?$/, ".")}` : "";
    return { bad: `${path} is not ${kind} — missing ${missing.join(", ")}.${said}` };
  }
  return { proof: obj };
}

// 3. Inclusion proof.
if (args.inclusion) {
  const read = readProofFile(args.inclusion, "an inclusion proof", [
    "log",
    "event.hash",
    "event.leaf_index",
    "proof",
    "checkpoint.tree_size",
    "checkpoint.root",
    "checkpoint.sig",
    "checkpoint.created_at",
  ]);
  if (read.bad) {
    inputUnusable = true;
    out.push(`UNUSABLE  inclusion  ${read.bad}`);
  } else {
    const pr = read.proof;
    const ok = verifyInclusion(pr.event.hash, pr.event.leaf_index, pr.checkpoint.tree_size, pr.proof, pr.checkpoint.root);
    const sigOk = edVerify(
      null,
      Buffer.from(`1f916.checkpoint.v1:${pr.log}:${pr.checkpoint.tree_size}:${pr.checkpoint.root}:${pr.checkpoint.created_at}`, "utf8"),
      key,
      b64u(pr.checkpoint.sig),
    );
    out.push(`${ok && sigOk ? "PASS" : "FAIL"}  inclusion  ${pr.log} event=${pr.event.id} index=${pr.event.leaf_index} under size=${pr.checkpoint.tree_size}`);
    if (!(ok && sigOk)) failed = true;
  }
}

// 4. Consistency proof.
if (args.consistency) {
  const read = readProofFile(args.consistency, "a consistency proof", [
    "log",
    "proof",
    "from.tree_size",
    "from.root",
    "to.tree_size",
    "to.root",
  ]);
  if (read.bad) {
    inputUnusable = true;
    out.push(`UNUSABLE  consistency  ${read.bad}`);
  } else {
    const pr = read.proof;
    const ok = verifyConsistency(pr.from.tree_size, pr.to.tree_size, pr.from.root, pr.to.root, pr.proof);
    out.push(`${ok ? "PASS" : "FAIL"}  consistency  ${pr.log} ${pr.from.tree_size} -> ${pr.to.tree_size} (append-only between checkpoints)`);
    if (!ok) failed = true;
  }
}

for (const line of out) console.log(line);
console.log("");
// witnessed implies anchored: it now requires a pinned witness key whose
// countersignature covers this root, and that witness verified the registry.
// witness-unusable ranks above the unwitnessed verdicts and below a real
// failure: the record may be fine, but the check the caller ASKED for could
// not be performed, and reporting that as though no witness had been
// requested makes the verdict string and the exit code — the two things
// people quote and branch on — byte-identical to a run that never asked.
const witnessUnusable = witnessAskedAndEmpty && !witnessed && !failed;
if (inputUnusablePeer) inputUnusable = true;
// A peer-only run (no checkpoint, no dossier) checked nothing but the
// comparison, so the comparison's outcome is its verdict; "unanchored" would
// describe a checkpoint that was never passed.
const peerOnly = args.peer && !args.checkpoint && !args.dossier;
const peerUnresolved = peerVerdict === "peer-unattributable" || peerVerdict === "peer-incomparable";
// input-unusable is the --inclusion/--consistency twin of witness-unusable, and
// it exists for the reason SearlesBox gave on protocol issue #6: the first fix
// stopped the crash and still answered `diverged`, which is the same string a
// genuinely broken proof produces. That reports "this registry's log is
// inconsistent" when the truth is "you handed me a 404 body". A guard that
// turns a crash into a WRONG claim is one verdict short of a fix. It ranks
// below a real failure, because if some other check actually diverged the
// caller needs to hear that first.
const verdict = failed
  ? "diverged"
  : inputUnusable
    ? "input-unusable"
    : peerOnly
      ? peerVerdict
    : witnessed
      ? "witnessed"
      : witnessUnusable
        ? "witness-unusable"
        : anchored
          ? "consistent-unwitnessed"
          : "unanchored";
console.log(`VERDICT: ${verdict}`);
if (verdict === "unanchored")
  console.log(
    "The file is internally consistent and NOTHING MORE. Every signature above was checked against a key carried in the same file, so a fabricated record signed with a freshly minted key produces this exact output. Anchor the run: --registry-key <the registry's published key, from the repo or the project site> and/or --witness-key <a pinned witness>. Until then, treat this as an unverified document.",
  );
if (verdict === "consistent-unwitnessed")
  console.log("The math holds against the pinned registry key, but no pinned witness countersignature was checked — this run trusts the registry's word for timing. Pass --witness with a day file plus --witness-key.");
if (verdict === "witness-unusable")
  console.log(
    "You passed --witness and the file carried no line this run could apply, so no countersignature was checked. The record itself may be perfectly sound: this verdict is about the RUN, not about the record. Re-fetch the day file (use curl -sf, so a 404 body cannot land in it as if it were data) and try again. This is deliberately not reported as 'consistent-unwitnessed', because asking and receiving nothing is a different state from never asking, and only the first one means somebody should go look.",
  );
if (verdict === "input-unusable")
  console.log(
    "A file you passed to --inclusion or --consistency is not a proof, so that check never ran. The commonest cause is saving an error response: ask the registry for a tree size it has no checkpoint for and it answers 404 with a JSON body that saves and parses perfectly. This is deliberately NOT reported as 'diverged', because 'I could not read your input' and 'the log is inconsistent' are opposite findings and only the second one is news about the registry. Re-fetch with curl -sf so an error body cannot land in the file as if it were data. Exit code 4.",
  );
if (verdict === "diverged") console.log("Keep every input file: a failing proof against a witnessed checkpoint is publishable evidence, not a bug report.");
if (peerVerdict === "peer-unattributable" || peerVerdict === "peer-incomparable")
  console.log(
    `The peer comparison could not complete (${peerVerdict}), so it says nothing for or against a split view. Exit code 5, shared with neither a pass nor a split. Pin the registry key with --registry-key, and compare day files that cover the same hours.`,
  );
if (peerVerdict === "no-split-seen-single-custody")
  console.log(
    "Both day files reached you by routes the registry's operator custodies, so a registry serving different histories could have served both of them the same one. Fetch one side from a witness or mirror outside that custody and pass its URL as --peer-from.",
  );
console.log("");
console.log("This run does NOT prove: who holds any private key (custody labels are claims in the record), that any event's content is true, or anything about rows labeled legacy_unsealed.");
process.exit(failed ? 1 : verdict === "input-unusable" ? 4 : verdict === "witness-unusable" ? 3 : peerUnresolved ? 5 : 0);
