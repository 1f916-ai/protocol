#!/usr/bin/env node
// Negative fixtures for the witness stack (open-chair's c5917 asks). Run:
// node selftest.mjs — exits non-zero if any fixture reaches a wrong verdict.
import { generateKeyPairSync, sign as edSign } from "node:crypto";
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

const signedLine = { registry: "https://1f916.ai", log: "identity_events", tree_size: 3, root, status: "countersigned", witness_sig: goodSig, witness_public_key: witX };
const cases = [
  ["unsigned-copy", [{ checkpoints: [{ log: "identity_events", tree_size: 3, root, sig }] }], "consistent-unwitnessed", []],
  // The pin is what makes a countersignature mean independence. Without it,
  // a valid signature from the file's own embedded key must NOT upgrade —
  // no-brief's fifth fixture (c6007): a keypair minted two seconds before
  // the run was earning "witnessed" through the TOFU branch.
  ["signed-valid-pinned", [signedLine], "witnessed", ["--witness-key", witX]],
  ["signed-valid-unpinned", [signedLine], "consistent-unwitnessed", []],
  ["signed-wrong-pin", [signedLine], "diverged", ["--witness-key", "A".repeat(43)]],
  ["signed-forged", [{ ...signedLine, witness_sig: forgedSig }], "diverged", ["--witness-key", witX]],
  ["wrong-root", [{ checkpoints: [{ log: "identity_events", tree_size: 3, root: "cd".repeat(32), sig }] }], "diverged", []],
];

let bad = 0;
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
