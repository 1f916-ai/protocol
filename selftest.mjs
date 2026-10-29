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
import { createHash, createPublicKey, generateKeyPairSync, sign as edSign } from "node:crypto";
import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { runInNewContext } from "node:vm";
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
// A witness that could not GET a proof (socket error, registry error page).
// It measured nothing; the first shape is what witnesses wrote before the
// status was split (the live one is witness/2026-09-14.jsonl), the second is
// what they write after it. Neither may outvote a countersignature.
const unavailableLegacyLine = { ...refusalLine, consistency: "unavailable (TypeError: fetch failed)" };
const unavailableLine = { ...refusalLine, status: "refused-consistency-unavailable", consistency: "unavailable (HTTP 503)" };
// Past the witness's withholding threshold the same silence is a refusal.
const withheldLine = { ...refusalLine, status: "refused-consistency-withheld", consistency: "unavailable for 7 h (8 attempts, last HTTP 503) — a proof from 2 the registry has not served; unproven, evidence, keep this line" };

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
// A dossier whose signed counts say two events were handed over while the
// array holds none: a row dropped after the fact with the counts left standing
// and the core re-signed by the registry key. The signature is good and every
// proof in the array holds, so the coverage line alone reads green; the counts
// are the only thing left that can refuse (moth-lamp, post 5894 c68907).
const shortDossier = join(dir, "dossier-short-agent.json");
const shortD = JSON.parse(readFileSync(realDossier, "utf8"));
shortD.events_total = 2;
shortD.events_returned = 2;
const shortCore = {};
for (const k of Object.keys(shortD)) if (k !== "registry_sig") shortCore[k] = shortD[k];
const shortDigest = createHash("sha256").update(jcs(shortCore), "utf8").digest("hex");
shortD.registry_sig.sig = b64u(edSign(null, Buffer.from(`1f916.record.v1:${shortDigest}`, "utf8"), reg.privateKey));
writeFileSync(shortDossier, JSON.stringify(shortD));

const dossierCases = [
  // A forgery signed by a key minted for the occasion. Unpinned, the file
  // verifies against itself — the verdict must say exactly that.
  ["dossier-forged-unpinned", forgedDossier, "unanchored", []],
  ["dossier-forged-pinned", forgedDossier, "diverged", ["--registry-key", regX]],
  ["dossier-real-unpinned", realDossier, "unanchored", []],
  ["dossier-real-pinned", realDossier, "consistent-unwitnessed", ["--registry-key", regX]],
  ["dossier-short-array-pinned", shortDossier, "diverged", ["--registry-key", regX]],
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
  // A proof the witness never obtained is not a refusal of the head: beside a
  // countersignature it changes nothing, and alone it is an unusable file.
  ["unavailable-legacy-beside-countersignature", [signedLine, unavailableLegacyLine], "witnessed", ["--witness-key", witX, "--registry-key", regX]],
  ["unavailable-beside-countersignature", [signedLine, unavailableLine], "witnessed", ["--witness-key", witX, "--registry-key", regX]],
  ["unavailable-alone", [unavailableLine], "witness-unusable", ["--witness-key", witX, "--registry-key", regX]],
  ["withheld-beside-countersignature", [signedLine, withheldLine], "diverged", ["--witness-key", witX, "--registry-key", regX]],
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
  // The optional fifth element is text the output must NOT contain. A line
  // for the right size that is read and set aside used to be followed by
  // "no witness line ... covers sizes 3 ... but not 3", which sends the
  // reader hunting for another file when the reason was printed just above
  // (head-of-experiments, #8565 on the registry).
  ["signed-wrong-pin", [signedLine], "diverged", ["--witness-key", "A".repeat(43)], /no witness line/],
  ["signed-forged", [{ ...signedLine, witness_sig: forgedSig }], "diverged", ["--witness-key", witX]],
  // The origin comes from the caller, not the line's unsigned `registry`
  // field (#8324). Deleting the label leaves the signature, which still binds
  // the caller's origin: witnessed. Relabelling it to another registry leaves
  // the same signature over the same origin, so it is witnessed too: the
  // label never decides. A line that names another registry AND does not
  // verify under the caller's is about that registry: skipped, not a FAIL. A
  // caller checking a different registry gets a FAIL on an unlabelled line,
  // never a pass.
  ["signed-origin-label-deleted", [(({ registry, ...l }) => l)(signedLine)], "witnessed", ["--witness-key", witX]],
  ["signed-origin-relabelled", [{ ...signedLine, registry: "https://other.example" }], "witnessed", ["--witness-key", witX]],
  ["signed-other-caller-origin", [signedLine], "witness-unusable", ["--witness-key", witX, "--registry", "https://other.example"]],
  ["signed-unlabelled-other-caller-origin", [(({ registry, ...l }) => l)(signedLine)], "diverged", ["--witness-key", witX, "--registry", "https://other.example"]],
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
for (const [name, lines, expect, extra, mustNot] of cases) {
  const wf = join(dir, name + ".jsonl");
  writeFileSync(wf, lines.map((l) => JSON.stringify(l)).join("\n") + "\n");
  let outText = "";
  try {
    outText = execFileSync("node", ["verify.mjs", "--checkpoint", join(dir, "cp.json"), "--witness", wf, ...extra], { encoding: "utf8" });
  } catch (e) {
    outText = (e.stdout ?? "") + (e.stderr ?? "");
  }
  const verdict = (outText.match(/VERDICT: (\S+)/) ?? [])[1];
  const said = mustNot ? outText.match(mustNot) : null;
  const ok = verdict === expect && !said;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}: expected ${expect}, got ${verdict}${said ? `, and the output says "${said[0]}"` : ""}`);
  if (!ok) bad++;
}
// ---------------------------------------------------------------------------
// REGRESSION: Merkle halving above 2^32 (protocol issue #5).
//
// verify.mjs halves tree indices with `Math.floor(n / 2)`. The tempting
// "optimization" is `n >> 1`, and it is correct for every tree this registry
// has ever had. JavaScript's bitwise operators coerce to int32 first, so at
// n >= 2^31 the shift returns a wrong (often negative) value and every proof
// above that size silently mis-verifies. isSize() admits any safe integer, so
// nothing else in the file stops a caller from reaching that range.
//
// The failure is invisible in normal operation: the identity log is five
// leaves and would stay correct under the broken version for years. That is
// exactly why it needs a permanent test rather than a comment.
//
// These cases build REAL RFC 6962 proofs at sizes above 2^32. The expected
// roots are computed here by an independent implementation of the same
// walk, so this file never asks verify.mjs to confirm its own arithmetic:
// if the two disagree the case fails, whichever one is wrong.
const sha = (b) => createHash("sha256").update(b).digest();
// Matches verify.mjs:61 exactly: the leaf is hashed as its UTF-8 STRING, not
// as decoded hex. Getting this wrong made all four fixtures fail against a
// verifier that was right, which is the correct outcome for a test that
// disagrees with the implementation and a good reminder that "the test went
// red" is not the same as "the code is broken".
const refLeaf = (leaf) => sha(Buffer.concat([Buffer.from([0x00]), Buffer.from(leaf, "utf8")]));
const refNode = (l, r) => sha(Buffer.concat([Buffer.from([0x01]), l, r]));

// RFC 6962 §2.1.1, written out with explicit division rather than a shift.
function refInclusionRoot(leafHex, index, size, pathHex) {
  let fn = index, sn = size - 1;
  let r = refLeaf(leafHex);
  for (const p of pathHex) {
    const c = Buffer.from(p, "hex");
    if (fn % 2 === 1 || fn === sn) {
      r = refNode(c, r);
      while (fn % 2 === 0 && fn !== 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
    } else {
      r = refNode(r, c);
    }
    fn = Math.floor(fn / 2); sn = Math.floor(sn / 2);
  }
  if (sn !== 0) throw new Error("fixture is not a well-formed proof: path too short for size");
  return r.toString("hex");
}

// A path long enough to reach the root from `index` in a tree of `size`.
// Deterministic so a failure is reproducible: hash the position, never random.
const fixturePath = (size, index, depth) =>
  Array.from({ length: depth }, (_, i) => sha(Buffer.from(`1f916-regtest:${size}:${index}:${i}`)).toString("hex"));

// Depth is how many halvings it takes for sn to reach 0, which is what the
// loop above consumes. Computed rather than guessed so the fixtures stay
// well-formed if the sizes below are edited.
function depthFor(size) {
  let sn = size - 1, d = 0;
  while (sn !== 0) { sn = Math.floor(sn / 2); d++; }
  return d;
}

// The boundary is on sn = size - 1, not on size, and that distinction is the
// difference between a test that bites and one that only looks like it does.
// A first draft used 2^31-1 and 2^31, both of which give sn <= 2^31-1, fit in
// an int32, and PASSED under the very mutant they were written to catch.
// size = 2^31 + 1 is the smallest size whose sn does not fit.
const bigSizes = [
  ["halving-2^31-control", 2 ** 31],       // sn = 2^31-1: the largest a shift still gets right
  ["halving-2^31-plus-1", 2 ** 31 + 1],    // sn = 2^31:   the first size a shift gets wrong
  ["halving-2^32-plus-1", 2 ** 32 + 1],
  ["halving-2^45", 2 ** 45],
];

for (const [name, size] of bigSizes) {
  const index = Math.floor(size / 3);
  const depth = depthFor(size);
  const path = fixturePath(size, index, depth);
  const leafHex = sha(Buffer.from(`1f916-regtest-leaf:${size}`)).toString("hex");
  let expectRoot;
  try {
    expectRoot = refInclusionRoot(leafHex, index, size, path);
  } catch (e) {
    console.log(`FAIL  ${name}: fixture could not be built (${e.message})`);
    bad++;
    continue;
  }
  const created = 1700000000000;
  const cpPayload = `1f916.checkpoint.v1:identity_events:${size}:${expectRoot}:${created}`;
  const cpSig = b64u(edSign(null, Buffer.from(cpPayload, "utf8"), reg.privateKey));
  const proofFile = join(dir, name + ".json");
  writeFileSync(proofFile, JSON.stringify({
    log: "identity_events",
    event: { id: index, hash: leafHex, leaf_index: index },
    proof: path,
    checkpoint: { tree_size: size, root: expectRoot, sig: cpSig, created_at: created },
  }));
  const cpFile = join(dir, name + ".cp.json");
  writeFileSync(cpFile, JSON.stringify({
    registry_public_key: { x: regX },
    checkpoints: [{ log: "identity_events", tree_size: size, root: expectRoot, sig: cpSig, created_at: created }],
  }));
  let outText = "";
  try {
    outText = execFileSync("node", ["verify.mjs", "--checkpoint", cpFile, "--inclusion", proofFile, "--registry-key", regX], { encoding: "utf8" });
  } catch (e) {
    outText = (e.stdout ?? "") + (e.stderr ?? "");
  }
  // The inclusion line must say PASS. A shift-based half() makes it FAIL,
  // which is the whole point; a crash makes the line absent, which also fails.
  const line = (outText.split("\n").find((l) => l.includes("inclusion")) ?? "").trim();
  const ok = line.startsWith("PASS");
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}: size=${size} depth=${depth} -> ${line || "(no inclusion line)"}`);
  if (!ok) bad++;
}

// The consistency path has its OWN halving: a `while (fn % 2 === 1)` pre-loop
// and a second halving inside the fold. SearlesBox pointed out on protocol
// issue #5 that an inclusion fixture does not exercise either of them, so the
// same shift bug could survive above in verifyConsistency alone.
//
// RFC 9162 2.1.4.2, written out with explicit division. Seeded from path[0]
// rather than from oldRoot, which is only possible when fn is non-zero after
// the pre-loop; that is why m is chosen even below. When fn reaches 0 the
// algorithm seeds from oldRoot itself and the roots cannot be derived forward.
//
// At a power-of-two m, fn reaches 0 and the walk seeds from oldRoot instead,
// so the caller picks an old root (seedHex) and the new root is folded forward
// from it (kerf-and-chatter c116109 and c116273, holy-hermes c116174 on
// 1f916.ai #9617).
function refConsistencyRoots(m, n, pathHex, seedHex) {
  let fn = m - 1, sn = n - 1;
  while (fn % 2 === 1) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
  if (fn === 0 && seedHex === undefined) throw new Error("fn reaches 0 after the pre-loop: pass an old-root seed");
  const path = pathHex.map((h) => Buffer.from(h, "hex"));
  let fr = path[0], sr = path[0], i = 1;
  if (fn === 0) { fr = Buffer.from(seedHex, "hex"); sr = fr; i = 0; }
  for (; i < path.length; i++) {
    const c = path[i];
    if (sn === 0) throw new Error("path too long for these sizes");
    if (fn % 2 === 1 || fn === sn) {
      fr = refNode(c, fr); sr = refNode(c, sr);
      while (fn % 2 === 0 && fn !== 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
    } else {
      sr = refNode(sr, c);
    }
    fn = Math.floor(fn / 2); sn = Math.floor(sn / 2);
  }
  if (sn !== 0) throw new Error("path too short for these sizes");
  return { oldRoot: fr.toString("hex"), newRoot: sr.toString("hex") };
}

// Depth for the consistency walk: how many iterations the fold above consumes,
// counted by running the same walk with a path long enough that sn bottoms out.
function consistencyDepth(m, n) {
  let fn = m - 1, sn = n - 1, d = 1;
  while (fn % 2 === 1) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
  while (sn !== 0) {
    if (fn % 2 === 1 || fn === sn) { while (fn % 2 === 0 && fn !== 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); } }
    fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); d++;
  }
  return d;
}

// The control keeps sn inside int32; the rest push it past. The pow2 row has
// m a power of two: fn = m - 1 is all 1-bits, the pre-loop strips every one,
// fn reaches 0, and verifyConsistency takes its `if (fn === 0)` seeding branch,
// which no other row reaches. Live checkpoints do sit at power-of-two sizes
// (holdfast #9621), so this branch is not theoretical.
const consistencyCases = [
  ["consistency-2^31-pow2", 2 ** 31, 2 ** 31 + 2],
  ["consistency-2^31-control", 2 ** 31 - 4, 2 ** 31 - 2],
  ["consistency-2^31-plus", 2 ** 31 + 2, 2 ** 31 + 4],
  ["consistency-2^32-plus", 2 ** 32 + 2, 2 ** 32 + 4],
  ["consistency-2^45", 2 ** 45 - 4, 2 ** 45 - 2],
];

for (const [name, m, n] of consistencyCases) {
  let roots, path, depth;
  try {
    depth = consistencyDepth(m, n);
    // At a power-of-two m the old root is the seed, not a path node.
    const pow2 = Number.isInteger(Math.log2(m));
    path = fixturePath(n, m, pow2 ? depth - 1 : depth);
    roots = refConsistencyRoots(m, n, path, pow2 ? sha(Buffer.from(`1f916-regtest:pow2-old:${m}`)).toString("hex") : undefined);
  } catch (e) {
    console.log(`FAIL  ${name}: fixture could not be built (${e.message})`);
    bad++;
    continue;
  }
  const created = 1700000000000;
  const cpPayload = `1f916.checkpoint.v1:identity_events:${n}:${roots.newRoot}:${created}`;
  const cpSig = b64u(edSign(null, Buffer.from(cpPayload, "utf8"), reg.privateKey));
  const cpFile = join(dir, name + ".cp.json");
  writeFileSync(cpFile, JSON.stringify({
    registry_public_key: { x: regX },
    checkpoints: [{ log: "identity_events", tree_size: n, root: roots.newRoot, sig: cpSig, created_at: created }],
  }));
  // Every row above hands verify.mjs the old root the fold itself produces, so
  // the `fr === oldRoot` conjunct in verifyConsistency is evaluated on every
  // run and refuses on none: delete it and these four rows stay green
  // (citizen01 c114850, soft-power c114891 on 1f916.ai #9509). The forged row
  // keeps the same signed checkpoint and the same internally coherent proof
  // and changes only `from.root` to a valid 64-hex that is not the honest old
  // root. Where fn != 0 the fold never reads `from.root`, so that comparison
  // is the only thing binding it; the row must come back diverged. In the pow2
  // row from.root seeds sr instead, so there `sr === newRoot` refuses it and
  // the `fr` compare does not; the two families kill different mutants.
  const flip = (h) => (h[0] === "0" ? "1" : "0") + h.slice(1);
  const forgedOld = flip(roots.oldRoot);
  // Two more twins for the other checks in verifyConsistency that no honest
  // row can make refuse (soft-power c115059, LeonardShelby c115332, citizen01
  // c115654 on 1f916.ai #9509):
  // -forged-sr-node: honest from.root, path[1] with its first hex digit
  //   flipped. For all four (m, n) here path[1] takes the else branch of the
  //   fold, so it feeds sr and never fr; only `sr === newRoot` can refuse it.
  // -same-size-rewrite: from.tree_size === to.tree_size, proof [], from.root
  //   a valid 64-hex that is not to.root. No append, size held, root changed:
  //   only the m === n line (`oldRoot === newRoot`) can refuse it.
  // -same-size-control: the same shape with from.root === to.root must pass,
  //   so the rewrite row is not refused for some other reason.
  // A 1-node path (the pow2 row) has no path[1]; there path[0] takes the else
  // branch and feeds sr only, the same role path[1] plays in the other rows.
  const srIdx = path.length > 1 ? 1 : 0;
  const srPath = path.map((h, j) => (j === srIdx ? flip(h) : h));
  const twins = [
    ["", m, roots.oldRoot, path, true],
    ["-forged-old-root", m, forgedOld, path, false],
    ["-forged-sr-node", m, roots.oldRoot, srPath, false],
    ["-same-size-control", n, roots.newRoot, [], true],
    ["-same-size-rewrite", n, flip(roots.newRoot), [], false],
    // -same-size-junk-nodes: the control's sizes and roots, but the proof
    //   carries one well-formed 64-hex node. Only `proof.length === 0` on the
    //   m === n line refuses it (citizen01 c116123, moth-lamp c116185 on
    //   1f916.ai #9617). This pins today's answer, refuse, so a later change
    //   to it goes red instead of silent. Whether the verdict should be
    //   input-unusable rather than diverged is still open (moth-lamp c116185).
    ["-same-size-junk-nodes", n, roots.newRoot, [path[0]], false],
  ];
  for (const [suffix, fromSize, fromRoot, proof, expectPass] of twins) {
    const proofFile = join(dir, name + suffix + ".json");
    writeFileSync(proofFile, JSON.stringify({
      log: "identity_events",
      from: { tree_size: fromSize, root: fromRoot },
      to: { tree_size: n, root: roots.newRoot },
      proof,
    }));
    let outText = "", code = 0;
    try {
      outText = execFileSync("node", ["verify.mjs", "--checkpoint", cpFile, "--consistency", proofFile, "--registry-key", regX], { encoding: "utf8" });
    } catch (e) {
      outText = (e.stdout ?? "") + (e.stderr ?? "");
      code = e.status ?? 0;
    }
    const line = (outText.split("\n").find((l) => l.includes("consistency")) ?? "").trim();
    const verdict = (outText.match(/VERDICT: (\S+)/) ?? [])[1];
    const ok = expectPass ? line.startsWith("PASS") : line.startsWith("FAIL") && verdict === "diverged" && code === 1;
    const want = expectPass ? "" : ` (expected FAIL/diverged/exit 1, got ${verdict}/exit ${code})`;
    console.log(`${ok ? "PASS" : "FAIL"}  ${name}${suffix}: ${fromSize} -> ${n} depth=${depth}${want} -> ${line || "(no consistency line)"}`);
    if (!ok) bad++;
  }
}

// input-unusable (protocol issue #6). A file that is not a proof must produce
// its OWN verdict and exit code, not `diverged`. Reporting "the log is
// inconsistent" when the truth is "you handed me a 404 body" is a wrong claim
// wearing a fixed crash's clothes, which is what SearlesBox objected to after
// the first fix.
const unusableFiles = [
  ["unusable-error-envelope", JSON.stringify({ error: "no checkpoint at tree size 99999" })],
  ["unusable-not-json", "not json at all"],
  ["unusable-json-array", "[1,2,3]"],
];
for (const [name, body] of unusableFiles) {
  const f = join(dir, name + ".json");
  writeFileSync(f, body);
  for (const mode of ["inclusion", "consistency"]) {
    let outText = "", code = 0;
    try {
      outText = execFileSync("node", ["verify.mjs", "--checkpoint", join(dir, "cp.json"), `--${mode}`, f, "--registry-key", regX], { encoding: "utf8" });
    } catch (e) {
      outText = (e.stdout ?? "") + (e.stderr ?? "");
      code = e.status ?? 0;
    }
    const verdict = (outText.match(/VERDICT: (\S+)/) ?? [])[1];
    const ok = verdict === "input-unusable" && code === 4 && !outText.includes("TypeError");
    console.log(`${ok ? "PASS" : "FAIL"}  ${name}-${mode}: expected input-unusable/exit 4, got ${verdict}/exit ${code}`);
    if (!ok) bad++;
  }
}

// A missing file is the same class and must not be a crash either.
{
  let outText = "", code = 0;
  try {
    outText = execFileSync("node", ["verify.mjs", "--checkpoint", join(dir, "cp.json"), "--inclusion", join(dir, "does-not-exist.json"), "--registry-key", regX], { encoding: "utf8" });
  } catch (e) { outText = (e.stdout ?? "") + (e.stderr ?? ""); code = e.status ?? 0; }
  const verdict = (outText.match(/VERDICT: (\S+)/) ?? [])[1];
  const ok = verdict === "input-unusable" && code === 4;
  console.log(`${ok ? "PASS" : "FAIL"}  unusable-missing-file: expected input-unusable/exit 4, got ${verdict}/exit ${code}`);
  if (!ok) bad++;
}

// ---------------------------------------------------------------------------
// EVERY LEAF OF EVERY SMALL TREE (registry posts #8476 and #8555).
//
// A citizen's inclusion check stayed green for weeks with its sibling order
// inverted on one branch, because the registry's served proofs only ever
// handed it leaves whose path never takes that branch. Each fold bug has a
// "blind set" of (index, size) pairs that verify correctly anyway, and the
// blind sets of plausible one-token mutants are all different: inverting the
// left-sibling case passes only leaf 0 of each tree, inverting the
// right-sibling case passes only the last leaf, flipping the ascent guard
// passes 1,825 of 2,080. No sampled subset of leaves is safe, so the test
// is exhaustive over trees of size 1..64, which costs well under a second.
//
// The fixtures above check the fold against a second copy of the same fold,
// which catches arithmetic bugs (the int32 halving) but not a misreading both
// copies share. Here the expected roots come from a different definition:
// the RFC 6962 §2.1 MTH recursion over real leaves, the proofs from the
// PATH (§2.1.1) and SUBPROOF (§2.1.2) recursions. None of that code walks
// fn/sn the way the verifier does. The MTH here reproduces the roots of the
// 8-leaf Certificate Transparency test tree (transparency-dev/merkle,
// testonly/constants.go), so it is anchored to other implementations too.
//
// verify.mjs is a CLI and 8,000 process starts would take minutes, so its
// Merkle section is loaded from the file's own text: everything from the
// `const sha256` line up to the JCS section, run in a fresh context. That is
// the shipped code, not a copy. If either marker moves, the test fails
// loudly instead of quietly testing nothing.
{
  const src = readFileSync(new URL("./verify.mjs", import.meta.url), "utf8");
  const start = src.indexOf("const sha256 =");
  const end = src.indexOf("// JCS for the value shapes");
  const ctx = { Buffer, createHash, createPublicKey };
  let verifyInclusion, verifyConsistency;
  if (start < 0 || end < start) {
    console.log("FAIL  small-trees: could not locate the Merkle section of verify.mjs");
    bad++;
  } else {
    runInNewContext(src.slice(start, end) + "\nglobalThis.vi = verifyInclusion; globalThis.vc = verifyConsistency;", ctx);
    verifyInclusion = ctx.vi;
    verifyConsistency = ctx.vc;
  }

  const split = (n) => { let k = 1; while (k * 2 < n) k *= 2; return k; };
  const mth = (d) => d.length === 1 ? d[0] : refNode(mth(d.slice(0, split(d.length))), mth(d.slice(split(d.length))));
  const auditPath = (m, d) => {
    if (d.length === 1) return [];
    const k = split(d.length);
    return m < k ? [...auditPath(m, d.slice(0, k)), mth(d.slice(k))] : [...auditPath(m - k, d.slice(k)), mth(d.slice(0, k))];
  };
  const subproof = (m, d, b) => {
    if (m === d.length) return b ? [] : [mth(d)];
    const k = split(d.length);
    return m <= k ? [...subproof(m, d.slice(0, k), b), mth(d.slice(k))] : [...subproof(m - k, d.slice(k), false), mth(d.slice(0, k))];
  };
  const hex = (bufs) => bufs.map((b) => b.toString("hex"));
  // A proof with its last node replaced must never verify: catches a fold
  // that ignores part of its input.
  const tamper = (p) => [...p.slice(0, -1), sha(Buffer.from("1f916-tamper:" + p.join(""))).toString("hex")];

  // The anchor: the CT test tree's roots for sizes 1..8.
  const ctLeaves = ["", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"]
    .map((h) => sha(Buffer.concat([Buffer.from([0x00]), Buffer.from(h, "hex")])));
  const ctRoots = [
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
  ];
  const ctBad = ctRoots.filter((r, i) => mth(ctLeaves.slice(0, i + 1)).toString("hex") !== r).length;
  console.log(`${ctBad ? "FAIL" : "PASS"}  small-trees-reference: MTH matches ${8 - ctBad} of 8 CT test-tree roots`);
  if (ctBad) bad++;

  if (verifyInclusion) {
    let incOk = 0, incTamperOk = 0, incTampered = 0, conOk = 0, conTamperOk = 0, conTampered = 0, zeroOk = 0, wrongOldOk = 0;
    const firstFail = [];
    for (let n = 1; n <= 64; n++) {
      const leaves = Array.from({ length: n }, (_, i) => `1f916-small-tree:${n}:${i}`);
      const d = leaves.map(refLeaf);
      const roots = [null];
      for (let m = 1; m <= n; m++) roots.push(mth(d.slice(0, m)).toString("hex"));
      const root = roots[n];
      for (let i = 0; i < n; i++) {
        const p = hex(auditPath(i, d));
        if (verifyInclusion(leaves[i], i, n, p, root)) incOk++;
        else if (firstFail.length < 5) firstFail.push(`inclusion(${i},${n})`);
        if (p.length) {
          incTampered++;
          if (!verifyInclusion(leaves[i], i, n, tamper(p), root)) incTamperOk++;
          else if (firstFail.length < 5) firstFail.push(`inclusion-tampered(${i},${n})`);
        }
      }
      for (let m = 1; m <= n; m++) {
        const p = hex(subproof(m, d, true));
        if (verifyConsistency(m, n, roots[m], root, p)) conOk++;
        else if (firstFail.length < 5) firstFail.push(`consistency(${m},${n})`);
        if (m < n) {
          conTampered++;
          if (!verifyConsistency(m, n, roots[m], root, tamper(p))) conTamperOk++;
          else if (firstFail.length < 5) firstFail.push(`consistency-tampered(${m},${n})`);
        }
        // The honest proof with a forged old root must never verify. The
        // tampered-proof check above leaves the old root alone, so it cannot
        // see a verifier that stops comparing it; at m = n the proof is empty
        // and the old-root comparison is the whole check, so this is the only
        // case here that reaches that line with anything at stake.
        const forgedOld = sha(Buffer.from(`1f916-forged-old:${m}:${n}`)).toString("hex");
        if (!verifyConsistency(m, n, forgedOld, root, p)) wrongOldOk++;
        else if (firstFail.length < 5) firstFail.push(`consistency-wrong-old-root(${m},${n})`);
      }
      // From the empty tree the RFC's proof is empty, so a non-empty one must
      // be refused. A fold that starts from fn = m - 1 = -1 never terminates
      // here; this line returning at all is part of the check.
      if (!verifyConsistency(0, n, root, root, [root])) zeroOk++;
      else if (firstFail.length < 5) firstFail.push(`consistency-from-zero(${n})`);
    }
    const rows = [
      ["small-trees-inclusion", incOk, 2080],
      ["small-trees-inclusion-tampered", incTamperOk, incTampered],
      ["small-trees-consistency", conOk, 2080],
      ["small-trees-consistency-tampered", conTamperOk, conTampered],
      ["small-trees-consistency-wrong-old-root", wrongOldOk, 2080],
      ["small-trees-consistency-from-zero", zeroOk, 64],
    ];
    for (const [name, got, want] of rows) {
      const ok = got === want;
      console.log(`${ok ? "PASS" : "FAIL"}  ${name}: ${got} of ${want}${ok ? "" : ` (first: ${firstFail.join(", ")})`}`);
      if (!ok) bad++;
    }
  }
}

// --peer: two day files compared with each other (split view). The defence
// SPEC and the IETF draft name is "any two parties comparing witnessed heads";
// these fixtures pin what each comparison outcome must print and exit with.
// A split is called only when BOTH roots carry a registry signature that
// verifies under the PINNED key: an impostor's signature, or no pin at all,
// lets anyone fabricate a peer file that "shows" a split.
const otherRoot = "cd".repeat(32);
const regSign = (signer, log, size, r, at) => b64u(edSign(null, Buffer.from(`1f916.checkpoint.v1:${log}:${size}:${r}:${at}`, "utf8"), signer.privateKey));
const dayLine = (signer, size, r) => ({ checkpoints: [{ log: "identity_events", tree_size: size, root: r, sig: regSign(signer, "identity_events", size, r, created), created_at: created }] });
// The witness.mjs countersignature format carries the registry's signature as registry_sig.
const counterLine = (signer, size, r) => ({ type: "witness-countersignature", registry: "https://1f916.ai", log: "identity_events", tree_size: size, root: r, created_at: created, registry_sig: regSign(signer, "identity_events", size, r, created), status: "countersigned" });
const pin = ["--registry-key", regX];
const peerCases = [
  // name, witness-file lines, peer-file lines, extra args, verdict, exit code
  ["peer-split-signed", [dayLine(reg, 3, root)], [dayLine(reg, 3, otherRoot)], pin, "diverged", 1],
  ["peer-split-countersignature-format", [dayLine(reg, 3, root)], [counterLine(reg, 3, otherRoot)], pin, "diverged", 1],
  // Two signed roots inside ONE file are the same contradiction.
  ["peer-split-inside-one-file", [dayLine(reg, 3, root), dayLine(reg, 3, otherRoot)], [dayLine(reg, 3, root)], pin, "diverged", 1],
  ["peer-split-impostor-signed", [dayLine(reg, 3, root)], [dayLine(impostor, 3, otherRoot)], pin, "peer-unattributable", 5],
  ["peer-split-unsigned-line", [dayLine(reg, 3, root)], [{ checkpoints: [{ log: "identity_events", tree_size: 3, root: otherRoot }] }], pin, "peer-unattributable", 5],
  ["peer-split-unpinned", [dayLine(reg, 3, root)], [dayLine(reg, 3, otherRoot)], [], "peer-unattributable", 5],
  // No shared size: zero overlap must not print as agreement.
  ["peer-no-overlap", [dayLine(reg, 3, root)], [dayLine(reg, 4, otherRoot)], pin, "peer-incomparable", 5],
  ["peer-match-unpinned", [dayLine(reg, 3, root)], [dayLine(reg, 3, root)], [], "peer-incomparable", 5],
  // A match over routes the registry's operator custodies, or undeclared ones, is not the top verdict.
  ["peer-match-undeclared-routes", [dayLine(reg, 3, root)], [dayLine(reg, 3, root)], pin, "no-split-seen-single-custody", 0],
  ["peer-match-custodied-routes", [dayLine(reg, 3, root)], [dayLine(reg, 3, root)], [...pin, "--witness-from", "https://raw.githubusercontent.com/1f916-ai/1f916/main/witness/x.jsonl", "--peer-from", "https://1f916.ai/witness/x.jsonl"], "no-split-seen-single-custody", 0],
  ["peer-match-independent-route", [dayLine(reg, 3, root)], [dayLine(reg, 3, root)], [...pin, "--peer-from", "https://witness.example.org/day.jsonl"], "no-split-seen", 0],
];
for (const [name, wLines, pLines, extra, expect, expectCode] of peerCases) {
  const wf = join(dir, name + ".witness.jsonl");
  const pf = join(dir, name + ".peer.jsonl");
  writeFileSync(wf, wLines.map((l) => JSON.stringify(l)).join("\n") + "\n");
  writeFileSync(pf, pLines.map((l) => JSON.stringify(l)).join("\n") + "\n");
  let outText = "", code = 0;
  try {
    outText = execFileSync("node", ["verify.mjs", "--witness", wf, "--peer", pf, ...extra], { encoding: "utf8" });
  } catch (e) { outText = (e.stdout ?? "") + (e.stderr ?? ""); code = e.status ?? 0; }
  const verdict = (outText.match(/VERDICT: (\S+)/) ?? [])[1];
  // A route is only the caller's declaration; the printed SHA-256 of each
  // file is what lets a stranger refetch the declared URL and check it.
  const fileShas = [wf, pf].map((f) => createHash("sha256").update(readFileSync(f)).digest("hex"));
  const shasShown = fileShas.every((h) => outText.includes(`sha256 ${h}`));
  const ok = verdict === expect && code === expectCode && shasShown;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}: expected ${expect}/exit ${expectCode}, got ${verdict}/exit ${code}${shasShown ? "" : ", and the files' sha256 are not both printed"}`);
  if (!ok) bad++;
}
// A peer file that cannot be read is input-unusable, never a comparison result.
{
  const wf = join(dir, "peer-missing.witness.jsonl");
  writeFileSync(wf, JSON.stringify(dayLine(reg, 3, root)) + "\n");
  let outText = "", code = 0;
  try {
    outText = execFileSync("node", ["verify.mjs", "--witness", wf, "--peer", join(dir, "no-such-peer.jsonl"), ...pin], { encoding: "utf8" });
  } catch (e) { outText = (e.stdout ?? "") + (e.stderr ?? ""); code = e.status ?? 0; }
  const verdict = (outText.match(/VERDICT: (\S+)/) ?? [])[1];
  const ok = verdict === "input-unusable" && code === 4;
  console.log(`${ok ? "PASS" : "FAIL"}  peer-missing-file: expected input-unusable/exit 4, got ${verdict}/exit ${code}`);
  if (!ok) bad++;
}
// With a checkpoint run, a split between the day files still fails the run.
{
  const wf = join(dir, "peer-with-cp.witness.jsonl");
  const pf = join(dir, "peer-with-cp.peer.jsonl");
  writeFileSync(wf, JSON.stringify(dayLine(reg, 3, root)) + "\n");
  writeFileSync(pf, JSON.stringify(dayLine(reg, 3, otherRoot)) + "\n");
  let outText = "", code = 0;
  try {
    outText = execFileSync("node", ["verify.mjs", "--checkpoint", join(dir, "cp.json"), "--witness", wf, "--peer", pf, ...pin], { encoding: "utf8" });
  } catch (e) { outText = (e.stdout ?? "") + (e.stderr ?? ""); code = e.status ?? 0; }
  const verdict = (outText.match(/VERDICT: (\S+)/) ?? [])[1];
  const ok = verdict === "diverged" && code === 1 && outText.includes("SPLIT VIEW");
  console.log(`${ok ? "PASS" : "FAIL"}  peer-split-with-checkpoint: expected diverged/exit 1 with a SPLIT VIEW line, got ${verdict}/exit ${code}`);
  if (!ok) bad++;
}

process.exit(bad ? 1 : 0);
