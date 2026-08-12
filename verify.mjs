#!/usr/bin/env node
// The 1F916 Protocol offline verifier. Single file, zero dependencies,
// no network access required or attempted. Node 18+.
//
//   node verify.mjs --checkpoint checkpoint.json [--witness lines.jsonl]
//                   [--inclusion proof.json] [--consistency proof.json]
//                   [--witness-key <b64url pinned witness public key>]
//   node verify.mjs --dossier record.json [--witness lines.jsonl]
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
if (!args.checkpoint && !args.dossier) usage();

function usage() {
  console.error("usage: node verify.mjs (--checkpoint checkpoint.json | --dossier record.json) [--witness day.jsonl] [--inclusion proof.json] [--consistency proof.json]");
  process.exit(2);
}

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

// RFC 6962 §2.1.1 inclusion verification.
function verifyInclusion(leaf, index, size, proof, root) {
  if (index >= size) return false;
  let fn = index, sn = size - 1, r = leafHash(leaf);
  for (const p of proof) {
    if (sn === 0) return false;
    const c = Buffer.from(p, "hex");
    if (fn % 2 === 1 || fn === sn) {
      r = nodeHash(c, r);
      if (fn % 2 === 0) while (fn % 2 === 0 && fn !== 0) { fn >>= 1; sn >>= 1; }
    } else {
      r = nodeHash(r, c);
    }
    fn >>= 1; sn >>= 1;
  }
  return sn === 0 && r.toString("hex") === root;
}

// RFC 9162 §2.1.4.2 consistency verification.
function verifyConsistency(m, n, oldRoot, newRoot, proof) {
  if (m > n) return false;
  if (m === n) return proof.length === 0 && oldRoot === newRoot;
  if (m === 0) return proof.length === 0;
  if (proof.length === 0) return false;
  let fn = m - 1, sn = n - 1;
  while (fn % 2 === 1) { fn >>= 1; sn >>= 1; }
  const path = proof.map((p) => Buffer.from(p, "hex"));
  let i = 0, fr, sr;
  if (fn === 0) { fr = Buffer.from(oldRoot, "hex"); sr = Buffer.from(oldRoot, "hex"); }
  else { fr = path[0]; sr = path[0]; i = 1; }
  for (; i < path.length; i++) {
    const c = path[i];
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      fr = nodeHash(c, fr); sr = nodeHash(c, sr);
      while (fn % 2 === 0 && fn !== 0) { fn >>= 1; sn >>= 1; }
    } else {
      sr = nodeHash(sr, c);
    }
    fn >>= 1; sn >>= 1;
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
    const key = ed25519Key(d.registry_sig.registry_public_key);
    const digest = createHash("sha256").update(jcs(core), "utf8").digest("hex");
    const ok = edVerify(null, Buffer.from(`1f916.record.v1:${digest}`, "utf8"), key, b64u(d.registry_sig.sig));
    out.push(`${ok ? "PASS" : "FAIL"}  registry signature over dossier core (${d.handle})`);
    if (!ok) failed = true;
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
  if (signedAtt) out.push(`PASS  ${signedAtt} attestation payload hashes intact (issuer signatures verify against the issuer's own record)`);
}

const cp = args.checkpoint ? JSON.parse(readFileSync(args.checkpoint, "utf8")) : dossierCheckpointFile;
const pubX = cp?.registry_public_key?.x;
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
    let signedOk = false, unsignedMatch = false, mismatch = false;
    for (const w of flat) {
      if (w.log !== row.log || w.tree_size !== row.tree_size) continue;
      if (w.root !== row.root) { mismatch = true; continue; }
      if (w.witness_sig && w.witness_public_key && w.status === "countersigned") {
        const pin = args["witness-key"];
        if (pin && pin !== w.witness_public_key) {
          out.push(`FAIL  witness key ${w.witness_public_key.slice(0, 12)}… does not match the pinned key  ${row.log} size=${row.tree_size}`);
          failed = true;
          continue;
        }
        const wpayload = `1f916.witness.v1:${w.registry ?? "https://1f916.ai"}:${row.log}:${row.tree_size}:${row.root}`;
        let ok = false;
        try { ok = edVerify(null, Buffer.from(wpayload, "utf8"), ed25519Key(w.witness_public_key), b64u(w.witness_sig)); } catch { ok = false; }
        if (ok) {
          signedOk = true;
          if (!pin) out.push(`....  TOFU: witness key ${w.witness_public_key.slice(0, 12)}… taken from the file itself — pin it with --witness-key to close the loop`);
        } else {
          out.push(`FAIL  witness countersignature does NOT verify  ${row.log} size=${row.tree_size}`);
          failed = true;
        }
      } else {
        unsignedMatch = true;
      }
    }
    if (signedOk) { witnessed = true; out.push(`PASS  witness countersignature verifies  ${row.log} size=${row.tree_size}`); }
    else if (mismatch) { failed = true; out.push(`FAIL  witness copy DISAGREES — keep both files, this is evidence  ${row.log} size=${row.tree_size}`); }
    else if (unsignedMatch) out.push(`....  unsigned witness copy matches ${row.log} size=${row.tree_size} — corroboration only; offline, this run cannot prove who wrote that file, so the verdict is not upgraded`);
    else out.push(`....  witness file has no entry for ${row.log} size=${row.tree_size} (not a failure; try a later file)`);
  }
}

// 3. Inclusion proof.
if (args.inclusion) {
  const pr = JSON.parse(readFileSync(args.inclusion, "utf8"));
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

// 4. Consistency proof.
if (args.consistency) {
  const pr = JSON.parse(readFileSync(args.consistency, "utf8"));
  const ok = verifyConsistency(pr.from.tree_size, pr.to.tree_size, pr.from.root, pr.to.root, pr.proof);
  out.push(`${ok ? "PASS" : "FAIL"}  consistency  ${pr.log} ${pr.from.tree_size} -> ${pr.to.tree_size} (append-only between checkpoints)`);
  if (!ok) failed = true;
}

for (const line of out) console.log(line);
console.log("");
const verdict = failed ? "diverged" : witnessed ? "witnessed" : "consistent-unwitnessed";
console.log(`VERDICT: ${verdict}`);
if (verdict === "consistent-unwitnessed")
  console.log("The math holds, but no independent witness copy was checked — this run trusts the registry's word for timing. Pass --witness with a day file from the witness repo.");
if (verdict === "diverged") console.log("Keep every input file: a failing proof against a witnessed checkpoint is publishable evidence, not a bug report.");
console.log("");
console.log("This run does NOT prove: who holds any private key (custody labels are claims in the record), that any event's content is true, or anything about rows labeled legacy_unsealed.");
process.exit(failed ? 1 : 0);
