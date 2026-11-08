#!/usr/bin/env node
// Generates the frozen two-stranger-gate corpus under testvectors/corpus/ and
// the expected-verdict manifest testvectors/expected-verdicts.json.
//
// WHY THIS EXISTS. The reference verifier verify.mjs is the normative gate, but
// until now the only inputs that exercised its five verdicts lived INLINE in
// selftest.mjs, rebuilt every run from fresh random keys. A second
// implementation (citizen01-sid's bundle, 0xRyanC's 1f916-verifier-py) had no
// byte-pinned corpus to run against, so "do we agree?" had no fixed question.
// This script freezes that question: it mirrors selftest.mjs's fixtures with
// DETERMINISTIC keys (fixed Ed25519 seeds, not generateKeyPairSync), writes the
// inputs as data files, runs verify.mjs against each, and records the verdict
// and exit status it ACTUALLY produced — never a hand-authored expectation, so
// the corpus cannot drift from the reference. Each vector also carries the
// verdict selftest.mjs documents as normative; if verify.mjs and that
// expectation ever disagree, THIS SCRIPT FAILS rather than baking the drift in.
//
// Re-running this script with an unchanged verify.mjs reproduces identical
// bytes (deterministic keys + JCS canonicalization), so the committed corpus is
// checkable by `git diff --exit-code` after a regen. Run: node testvectors/make-corpus.mjs
import { createHash, createPrivateKey, createPublicKey, sign as edSign } from "node:crypto";
import { writeFileSync, mkdirSync, rmSync, readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const repo = dirname(here);
const corpusDir = join(here, "corpus");

// --- deterministic Ed25519 keys from fixed 32-byte seeds (PKCS8 DER wrap) ---
const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
function keyFromSeed(byte) {
  const seed = Buffer.alloc(32, byte);
  const priv = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]), format: "der", type: "pkcs8" });
  const x = createPublicKey(priv).export({ format: "jwk" }).x; // base64url raw 32-byte public key
  return { priv, x };
}
// Fixed seeds: registry 0x11, witness 0x22, impostor 0x33. TEST KEYS ONLY —
// their private halves are the constant seeds above and hold nothing.
const reg = keyFromSeed(0x11);
const wit = keyFromSeed(0x22);
const impostor = keyFromSeed(0x33);
const b64u = (b) => Buffer.from(b).toString("base64url");

// JCS for the value shapes a dossier contains — byte-identical to verify.mjs.
function jcs(v) {
  if (v === null || typeof v === "boolean" || typeof v === "number") return JSON.stringify(v);
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(jcs).join(",")}]`;
  return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${jcs(v[k])}`).join(",")}}`;
}

// --- the shared checkpoint (identity_events @ size 3) and its witness head ---
const root = "ab".repeat(32);
const created = 1700000000000;
const cpPayload = `1f916.checkpoint.v1:identity_events:3:${root}:${created}`;
const sig = b64u(edSign(null, Buffer.from(cpPayload, "utf8"), reg.priv));
const checkpoint = { registry_public_key: { x: reg.x }, checkpoints: [{ log: "identity_events", tree_size: 3, root, sig, created_at: created }] };

const wPayload = `1f916.witness.v1:https://1f916.ai:identity_events:3:${root}`;
const goodSig = b64u(edSign(null, Buffer.from(wPayload, "utf8"), wit.priv));
const forgedSig = b64u(edSign(null, Buffer.from(wPayload + "x", "utf8"), wit.priv));

// Every line witness.mjs writes carries type:"witness-countersignature"
// (witness.mjs:147), and so does every live day file; the corpus must emit the
// producer's shape, not the inline test fixture's, so a verifier that follows
// witness.mjs is not penalised for requiring the field it is handed in
// production. verify.mjs is indifferent to type, so the frozen verdicts are
// unchanged (citizen01-sid, 0xRyanC, issue #10).
const signedLine = { type: "witness-countersignature", registry: "https://1f916.ai", log: "identity_events", tree_size: 3, root, status: "countersigned", consistency: "verified from 2", witness_sig: goodSig, witness_public_key: wit.x };
const firstObsLine = { ...signedLine, consistency: "first observation" };
const refusalLine = { type: "witness-countersignature", registry: "https://1f916.ai", log: "identity_events", tree_size: 3, root, status: "refused-consistency-failure", consistency: "FAILED — possible rewrite, evidence, keep this line" };
const unavailableLegacyLine = { ...refusalLine, consistency: "unavailable (TypeError: fetch failed)" };
const unavailableLine = { ...refusalLine, status: "refused-consistency-unavailable", consistency: "unavailable (HTTP 503)" };
const withheldLine = { ...refusalLine, status: "refused-consistency-withheld", consistency: "unavailable for 7 h (8 attempts, last HTTP 503) — a proof from 2 the registry has not served; unproven, evidence, keep this line" };

// --- dossiers ---
const DOSSIER_CORE_MEMBERS = ["protocol","handle","citizen_id","model","since","keys","bindings","events","events_total","events_returned","events_has_more","attestations_about","checkpoint","witnesses"];
function makeDossier(signer, signerX, handle) {
  const core = { protocol: "1f916/0", handle, citizen_id: 1, model: "test", since: created, keys: [], bindings: [], events: [], events_total: 0, events_returned: 0, events_has_more: false, attestations_about: [], checkpoint: null, witnesses: [] };
  const digest = createHash("sha256").update(jcs(core), "utf8").digest("hex");
  return { ...core, registry_sig: { sig: b64u(edSign(null, Buffer.from(`1f916.record.v1:${digest}`, "utf8"), signer.priv)), over: "1f916.record.v1:sha256(JCS(dossier-core))", registry_public_key: signerX } };
}
const realDossier = makeDossier(reg, reg.x, "real-agent");
const forgedDossier = makeDossier(impostor, impostor.x, "totally-legit-agent");
// Counts say two events handed over; the array holds none. Core re-signed by
// the registry key, so the signature is good and the drop shows only in counts.
const shortDossier = JSON.parse(JSON.stringify(realDossier));
shortDossier.handle = "short-agent";
shortDossier.events_total = 2;
shortDossier.events_returned = 2;
const shortCore = {};
for (const k of DOSSIER_CORE_MEMBERS) if (k in shortDossier) shortCore[k] = shortDossier[k];
shortDossier.registry_sig.sig = b64u(edSign(null, Buffer.from(`1f916.record.v1:${createHash("sha256").update(jcs(shortCore), "utf8").digest("hex")}`, "utf8"), reg.priv));

// --- the vector table. Each entry mirrors a selftest.mjs fixture with the
// verdict it documents as normative. kind drives how verify.mjs is invoked. ---
const stripReg = ({ registry, ...l }) => l;
const vectors = [
  // dossier vectors (verify --dossier <file> [extra])
  { name: "dossier-forged-unpinned", kind: "dossier", dossier: forgedDossier, extra: [], verdict: "unanchored" },
  { name: "dossier-forged-pinned", kind: "dossier", dossier: forgedDossier, extra: ["--registry-key", reg.x], verdict: "diverged" },
  { name: "dossier-real-unpinned", kind: "dossier", dossier: realDossier, extra: [], verdict: "unanchored" },
  { name: "dossier-real-pinned", kind: "dossier", dossier: realDossier, extra: ["--registry-key", reg.x], verdict: "consistent-unwitnessed" },
  { name: "dossier-short-array-pinned", kind: "dossier", dossier: shortDossier, extra: ["--registry-key", reg.x], verdict: "diverged" },
  // checkpoint + witness vectors (verify --checkpoint cp.json --witness <file> [extra])
  { name: "unsigned-copy", kind: "witness", lines: [{ checkpoints: [{ log: "identity_events", tree_size: 3, root, sig }] }], extra: ["--registry-key", reg.x], verdict: "consistent-unwitnessed" },
  { name: "unsigned-copy-unanchored", kind: "witness", lines: [{ checkpoints: [{ log: "identity_events", tree_size: 3, root, sig }] }], extra: [], verdict: "unanchored" },
  { name: "signed-valid-pinned", kind: "witness", lines: [signedLine], extra: ["--witness-key", wit.x], verdict: "witnessed" },
  { name: "first-observation-pinned", kind: "witness", lines: [firstObsLine], extra: ["--witness-key", wit.x, "--registry-key", reg.x], verdict: "consistent-unwitnessed" },
  { name: "witness-refusal", kind: "witness", lines: [refusalLine], extra: ["--registry-key", reg.x], verdict: "diverged" },
  { name: "refusal-beside-countersignature", kind: "witness", lines: [signedLine, refusalLine], extra: ["--witness-key", wit.x, "--registry-key", reg.x], verdict: "diverged" },
  { name: "unavailable-legacy-beside-countersignature", kind: "witness", lines: [signedLine, unavailableLegacyLine], extra: ["--witness-key", wit.x, "--registry-key", reg.x], verdict: "witnessed" },
  { name: "unavailable-beside-countersignature", kind: "witness", lines: [signedLine, unavailableLine], extra: ["--witness-key", wit.x, "--registry-key", reg.x], verdict: "witnessed" },
  { name: "unavailable-alone", kind: "witness", lines: [unavailableLine], extra: ["--witness-key", wit.x, "--registry-key", reg.x], verdict: "witness-unusable" },
  { name: "withheld-beside-countersignature", kind: "witness", lines: [signedLine, withheldLine], extra: ["--witness-key", wit.x, "--registry-key", reg.x], verdict: "diverged" },
  { name: "witness-file-empty", kind: "witness", lines: [], extra: ["--witness-key", wit.x, "--registry-key", reg.x], verdict: "witness-unusable" },
  { name: "witness-file-wrong-log", kind: "witness", lines: [{ ...signedLine, log: "ledger" }], extra: ["--witness-key", wit.x, "--registry-key", reg.x], verdict: "witness-unusable" },
  { name: "signed-valid-unpinned", kind: "witness", lines: [signedLine], extra: [], verdict: "unanchored" },
  { name: "signed-wrong-pin", kind: "witness", lines: [signedLine], extra: ["--witness-key", "A".repeat(43)], verdict: "diverged" },
  { name: "signed-forged", kind: "witness", lines: [{ ...signedLine, witness_sig: forgedSig }], extra: ["--witness-key", wit.x], verdict: "diverged" },
  { name: "signed-origin-label-deleted", kind: "witness", lines: [stripReg(signedLine)], extra: ["--witness-key", wit.x], verdict: "witnessed" },
  { name: "signed-origin-relabelled", kind: "witness", lines: [{ ...signedLine, registry: "https://other.example" }], extra: ["--witness-key", wit.x], verdict: "witnessed" },
  { name: "signed-other-caller-origin", kind: "witness", lines: [signedLine], extra: ["--witness-key", wit.x, "--registry", "https://other.example"], verdict: "witness-unusable" },
  { name: "signed-unlabelled-other-caller-origin", kind: "witness", lines: [stripReg(signedLine)], extra: ["--witness-key", wit.x, "--registry", "https://other.example"], verdict: "diverged" },
  { name: "wrong-root", kind: "witness", lines: [{ checkpoints: [{ log: "identity_events", tree_size: 3, root: "cd".repeat(32), sig }] }], extra: ["--registry-key", reg.x], verdict: "diverged" },
];

// Exit status each verdict must carry (verify.mjs tail): the two things callers
// branch on. witnessed/consistent-unwitnessed/unanchored -> 0; diverged -> 1;
// witness-unusable -> 3; input-unusable -> 4.
const EXIT_FOR = { witnessed: 0, "consistent-unwitnessed": 0, unanchored: 0, diverged: 1, "witness-unusable": 3, "input-unusable": 4 };

rmSync(corpusDir, { recursive: true, force: true });
mkdirSync(corpusDir, { recursive: true });

function run(argv) {
  try {
    const stdout = execFileSync("node", ["verify.mjs", ...argv], { cwd: repo, encoding: "utf8" });
    return { stdout, code: 0 };
  } catch (e) {
    return { stdout: (e.stdout ?? "") + (e.stderr ?? ""), code: e.status ?? -1 };
  }
}

let bad = 0;
const manifestVectors = [];
for (const v of vectors) {
  const vdir = join(corpusDir, v.name);
  mkdirSync(vdir, { recursive: true });
  let argv, files;
  if (v.kind === "dossier") {
    const p = join(vdir, "dossier.json");
    writeFileSync(p, JSON.stringify(v.dossier));
    argv = ["--dossier", p, ...v.extra];
    files = { dossier: "dossier.json" };
  } else {
    const cp = join(vdir, "checkpoint.json");
    writeFileSync(cp, JSON.stringify(checkpoint));
    const wf = join(vdir, "witness.jsonl");
    writeFileSync(wf, v.lines.map((l) => JSON.stringify(l)).join("\n") + "\n");
    argv = ["--checkpoint", cp, "--witness", wf, ...v.extra];
    files = { checkpoint: "checkpoint.json", witness: "witness.jsonl" };
  }
  // Arg paths in the manifest are repo-relative so the manifest is portable.
  const relExtra = v.extra.map((a) => a);
  const { stdout, code } = run(argv);
  const got = (stdout.match(/VERDICT: (\S+)/) ?? [])[1];
  const expectExit = EXIT_FOR[v.verdict];
  const ok = got === v.verdict && code === expectExit;
  if (!ok) { bad++; console.log(`FAIL  ${v.name}: documented ${v.verdict}/exit ${expectExit}, verify.mjs produced ${got}/exit ${code}`); }
  else console.log(`ok    ${v.name}: ${got} / exit ${code}`);
  manifestVectors.push({ name: v.name, kind: v.kind, files, args: relExtra, expected_verdict: got, expected_exit: code });
}

// Pin to the commit that last touched verify.mjs, not HEAD: the manifest's
// claim is "these are the verdicts verify.mjs produces", so the pin must move
// only when the verifier does. Pinning to HEAD would make the CI regen-and-diff
// guard fail on every unrelated commit (the corpus commit itself included).
const commit = execFileSync("git", ["log", "-1", "--format=%H", "--", "verify.mjs"], { cwd: repo, encoding: "utf8" }).trim();
const specVersion = (readFileSync(join(repo, "SPEC.md"), "utf8").match(/\*\*Version:\s*([^\s.]+(?:\.[^\s.]+)*(?:-\w+)?)/) ?? [])[1] ?? "unknown";
const manifest = {
  corpus: "1f916-protocol two-stranger-gate frozen verdict corpus",
  generated_by: "testvectors/make-corpus.mjs (deterministic; re-run and git diff to check)",
  spec_version: specVersion,
  pinned_commit: commit,
  reference_verifier: "verify.mjs",
  canonicalization: "JCS over {null,bool,number,string,array,object}: object keys sorted, scalars via JSON.stringify, arrays recursive. See testvectors/CONTRACT.md.",
  signed_byte_boundaries: {
    checkpoint: "1f916.checkpoint.v1:<log>:<tree_size>:<root>:<created_at>  (UTF-8, Ed25519 by the registry key)",
    witness: "1f916.witness.v1:<caller-origin>:<log>:<tree_size>:<root>  (UTF-8, Ed25519 by the witness key)",
    dossier: "1f916.record.v1:<hex sha256(JCS(dossier-core))>  (UTF-8, Ed25519 by the registry key)",
  },
  dossier_core_members: DOSSIER_CORE_MEMBERS.concat(["next_events_since (optional, included only when present)"]),
  registry_public_key_x: reg.x,
  witness_public_key_x: wit.x,
  exit_status_by_verdict: EXIT_FOR,
  vectors: manifestVectors,
};
writeFileSync(join(here, "expected-verdicts.json"), JSON.stringify(manifest, null, 2) + "\n");

console.log(`\n${manifestVectors.length} vectors written; ${bad} disagreed with the documented verdict/exit.`);
const verdicts = new Set(manifestVectors.map((v) => v.expected_verdict));
console.log(`verdicts covered: ${[...verdicts].sort().join(", ")}`);
process.exit(bad ? 1 : 0);
