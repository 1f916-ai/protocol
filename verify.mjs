#!/usr/bin/env node
// The 1F916 Protocol offline verifier. Single file, zero dependencies,
// no network access required or attempted. Node 18+.
//
//   node verify.mjs --checkpoint checkpoint.json [--witness day.jsonl]
//                   [--inclusion proof.json] [--consistency proof.json]
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
if (!args.checkpoint) usage();

function usage() {
  console.error("usage: node verify.mjs --checkpoint checkpoint.json [--witness day.jsonl] [--inclusion proof.json] [--consistency proof.json]");
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

const out = [];
let failed = false;
let witnessed = false;

const cp = JSON.parse(readFileSync(args.checkpoint, "utf8"));
const pubX = cp.registry_public_key?.x;
if (!pubX) { console.error("checkpoint file carries no registry_public_key.x"); process.exit(2); }
const key = ed25519Key(pubX);

// 1. Registry signatures over every checkpoint in the file.
for (const row of cp.checkpoints ?? []) {
  const payload = `1f916.checkpoint.v1:${row.log}:${row.tree_size}:${row.root}:${row.created_at}`;
  const ok = edVerify(null, Buffer.from(payload, "utf8"), key, b64u(row.sig));
  out.push(`${ok ? "PASS" : "FAIL"}  registry signature  ${row.log} size=${row.tree_size}`);
  if (!ok) failed = true;
}

// 2. Witness cross-check: the same (log, tree_size) must carry the same root
// in the witness's copy. The witness file is the anchor the registry cannot
// rewrite; a mismatch is not an error in this run, it is evidence.
if (args.witness) {
  const lines = readFileSync(args.witness, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
  for (const row of cp.checkpoints ?? []) {
    let seen = false, match = false;
    for (const line of lines) {
      for (const w of Array.isArray(line.checkpoints) ? line.checkpoints : []) {
        if (w.log === row.log && w.tree_size === row.tree_size) {
          seen = true;
          if (w.root === row.root && w.sig === row.sig) match = true;
          else failed = true;
        }
      }
    }
    if (seen && match) { witnessed = true; out.push(`PASS  witness copy agrees  ${row.log} size=${row.tree_size}`); }
    else if (seen) out.push(`FAIL  witness copy DISAGREES — keep both files, this is evidence  ${row.log} size=${row.tree_size}`);
    else out.push(`....  witness file has no entry for ${row.log} size=${row.tree_size} (not a failure; try a later day file)`);
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
