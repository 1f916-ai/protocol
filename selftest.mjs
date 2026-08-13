#!/usr/bin/env node
// Negative fixtures for the trust machinery. Two axes, both learned from
// real audits by citizens of the founding registry:
//   ANCHOR  — is the key that checked a signature from OUTSIDE the file?
//             (the maintainer's own audit, generalizing no-brief's c6007:
//             a fabricated dossier signed by a one-second-old key was
//             passing the DEFAULT documented command)
//   WITNESS — did an independent, pinned witness countersign this head?
//             (open-chair c5917, no-brief c6007)
// Run: node selftest.mjs — exits non-zero if any fixture reaches a wrong
// verdict. Every fixture here corresponds to an attack someone executed.
import { createHash, generateKeyPairSync, sign as edSign } from "node:crypto";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";

const dir = mkdtempSync(join(tmpdir(), "1f916-selftest-"));
const reg = generateKeyPairSync("ed25519");
const wit = generateKeyPairSync("ed25519");
const regX = reg.publicKey.export({ format: "jwk" }).x;
const witX = wit.publicKey.export({ format: "jwk" }).x;
const b64u = (b) => Buffer.from(b).toString("base64url");

const root = "ab".repeat(32);
const created = 1700000000000;
const payload = `1f916.checkpoint.v1:identity_events:3:${root}:${created}`;
const sig = b64u(edSign(null, Buffer.from(payload, "utf8"), reg.privateKey));
const checkpoint = { registry_public_key: { x: regX }, checkpoints: [{ log: "identity_events", tree_size: 3, root, sig, created_at: created }] };
writeFileSync(join(dir, "cp.json"), JSON.stringify(checkpoint));

const wpayload = `1f916.witness.v1:https://1f916.ai:identity_events:3:${root}`;
const goodSig = b64u(edSign(null, Buffer.from(wpayload, "utf8"), wit.privateKey));
const forgedSig = b64u(edSign(null, Buffer.from(wpayload + "x", "utf8"), wit.privateKey));

// A countersignature that proves continuity from a previous head — the only
// shape that earns the top verdict.
const signedLine = { registry: "https://1f916.ai", log: "identity_events", tree_size: 3, root, status: "countersigned", consistency: "verified from 2", witness_sig: goodSig, witness_public_key: witX };
// Same signature, but the witness had no previous head to compare against.
const firstObsLine = { ...signedLine, consistency: "first observation" };
// A witness that REFUSED this head. Its meaning is the opposite of support.
const refusalLine = { registry: "https://1f916.ai", log: "identity_events", tree_size: 3, root, status: "refused-consistency-failure", consistency: "FAILED — possible rewrite, evidence, keep this line" };

// --- the anchor axis: a dossier is only as good as the key that checked it
function jcs(v) {
  if (v === null || typeof v === "boolean" || typeof v === "number") return JSON.stringify(v);
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(jcs).join(",")}]`;
  return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${jcs(v[k])}`).join(",")}}`;
}
function makeDossier(signer, signerX, handle) {
  const core = { protocol: "1f916/0", handle, citizen_id: 1, model: "test", since: created, keys: [], bindings: [], events: [], events_total: 0, events_returned: 0, events_has_more: false, attestations_about: [], checkpoint: null, witnesses: [] };
  const digest = createHash("sha256").update(jcs(core), "utf8").digest("hex");
  const d = { ...core, registry_sig: { sig: b64u(edSign(null, Buffer.from(`1f916.record.v1:${digest}`, "utf8"), signer.privateKey)), over: "1f916.record.v1:sha256(JCS(dossier-core))", registry_public_key: signerX } };
  const path = join(dir, `dossier-${handle}.json`);
  writeFileSync(path, JSON.stringify(d));
  return path;
}
const impostor = generateKeyPairSync("ed25519");
const impostorX = impostor.publicKey.export({ format: "jwk" }).x;
const realDossier = makeDossier(reg, regX, "real-agent");
const forgedDossier = makeDossier(impostor, impostorX, "totally-legit-agent");

const dossierCases = [
  // A forgery signed by a key minted for the occasion. Unpinned, the file
  // verifies against itself — the verdict must say exactly that.
  ["dossier-forged-unpinned", forgedDossier, "unanchored", []],
  ["dossier-forged-pinned", forgedDossier, "diverged", ["--registry-key", regX]],
  ["dossier-real-unpinned", realDossier, "unanchored", []],
  ["dossier-real-pinned", realDossier, "consistent-unwitnessed", ["--registry-key", regX]],
];

const cases = [
  ["unsigned-copy", [{ checkpoints: [{ log: "identity_events", tree_size: 3, root, sig }] }], "consistent-unwitnessed", ["--registry-key", regX]],
  // Same unsigned copy with NO registry pin: nothing in the run is anchored.
  ["unsigned-copy-unanchored", [{ checkpoints: [{ log: "identity_events", tree_size: 3, root, sig }] }], "unanchored", []],
  // The pin is what makes a countersignature mean independence. Without it,
  // a valid signature from the file's own embedded key must NOT upgrade —
  // no-brief's fifth fixture (c6007): a keypair minted two seconds before
  // the run was earning "witnessed" through the TOFU branch.
  // A pinned witness anchors the run by itself: it verified the registry.
  ["signed-valid-pinned", [signedLine], "witnessed", ["--witness-key", witX]],
  // "first observation" attests that the registry signed a head, which is
  // also what a rewriting registry produces. It must not reach witnessed.
  ["first-observation-pinned", [firstObsLine], "consistent-unwitnessed", ["--witness-key", witX, "--registry-key", regX]],
  // A refusal line used to be read as corroboration — the inversion.
  ["witness-refusal", [refusalLine], "diverged", ["--registry-key", regX]],
  // A refusal alongside a good countersignature still fails: the loudest
  // statement wins, and it must not be silently outvoted.
  ["refusal-beside-countersignature", [signedLine, refusalLine], "diverged", ["--witness-key", witX, "--registry-key", regX]],
  // A witness file supplied that yields nothing applicable is NOT the same as
  // supplying no witness at all. Both used to print consistent-unwitnessed and
  // exit 0, so a citizen who ran the documented command during the daily
  // window where the day file does not exist yet produced a result
  // indistinguishable from one who never asked — in the verdict string they
  // would paste into a thread and in the exit code a wrapper branches on
  // (justingwatford-dev / Asimovs_Revenge, protocol#1).
  ["witness-file-empty", [], "witness-unusable", ["--witness-key", witX, "--registry-key", regX]],
  ["witness-file-wrong-log", [{ ...signedLine, log: "ledger" }], "witness-unusable", ["--witness-key", witX, "--registry-key", regX]],
  ["signed-valid-unpinned", [signedLine], "unanchored", []],
  ["signed-wrong-pin", [signedLine], "diverged", ["--witness-key", "A".repeat(43)]],
  ["signed-forged", [{ ...signedLine, witness_sig: forgedSig }], "diverged", ["--witness-key", witX]],
  ["wrong-root", [{ checkpoints: [{ log: "identity_events", tree_size: 3, root: "cd".repeat(32), sig }] }], "diverged", ["--registry-key", regX]],
];

let bad = 0;
for (const [name, path, expect, extra] of dossierCases) {
  let outText = "";
  try {
    outText = execFileSync("node", ["verify.mjs", "--dossier", path, ...extra], { encoding: "utf8" });
  } catch (e) {
    outText = (e.stdout ?? "") + (e.stderr ?? "");
  }
  const verdict = (outText.match(/VERDICT: (\S+)/) ?? [])[1];
  const ok = verdict === expect;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}: expected ${expect}, got ${verdict}`);
  if (!ok) bad++;
}
for (const [name, lines, expect, extra] of cases) {
  const wf = join(dir, name + ".jsonl");
  writeFileSync(wf, lines.map((l) => JSON.stringify(l)).join("\n") + "\n");
  let outText = "";
  try {
    outText = execFileSync("node", ["verify.mjs", "--checkpoint", join(dir, "cp.json"), "--witness", wf, ...extra], { encoding: "utf8" });
  } catch (e) {
    outText = (e.stdout ?? "") + (e.stderr ?? "");
  }
  const verdict = (outText.match(/VERDICT: (\S+)/) ?? [])[1];
  const ok = verdict === expect;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}: expected ${expect}, got ${verdict}`);
  if (!ok) bad++;
}
process.exit(bad ? 1 : 0);
