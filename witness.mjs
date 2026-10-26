#!/usr/bin/env node
// A complete, independent witness for any 1f916-protocol registry.
// Single file, zero dependencies. Node 18+.
//
//   node witness.mjs --registry https://1f916.ai --state ./witness-state
//
// Each run (put it in cron, a GitHub Action, anything hourly-ish):
//   1. fetches GET /api/checkpoint,
//   2. verifies the registry signature,
//   3. fetches a consistency proof from the last head this witness saw and
//      verifies the log only appended — a failed proof is recorded loudly,
//      never skipped,
//   4. countersigns {log, tree_size, root} with YOUR Ed25519 key,
//   5. appends one JSON line per log to <state>/countersignatures.jsonl.
//
// Publish that file anywhere the registry cannot touch (your repo, your
// site), then register the pointer: POST /api/witness {name, url,
// public_key}. Your first run generates a keypair in <state>/witness-key.json
// — back it up; it IS your witness identity.
//
// Witness independence is the security parameter of the whole protocol:
// the more of you there are, the less anyone has to trust the registry.

import { createHash, createPublicKey, createPrivateKey, generateKeyPairSync, sign as edSign, verify as edVerify } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync, appendFileSync } from "node:fs";
import { join } from "node:path";

const args = {};
for (let i = 2; i < process.argv.length; i += 2) args[process.argv[i]?.slice(2)] = process.argv[i + 1];
const registry = (args.registry ?? "https://1f916.ai").replace(/\/$/, "");
let stateDir = args.state ?? "./witness-state";

const b64u = (b) => Buffer.from(b).toString("base64url");
const fromB64u = (s) => Buffer.from(s, "base64url");
const sha256 = (b) => createHash("sha256").update(b).digest();
const nodeHash = (l, r) => sha256(Buffer.concat([Buffer.from([1]), l, r]));

// --- witness identity (loaded inside run(): --selftest points stateDir at a
// throwaway directory before the identity is read or created) ---
function loadIdentity() {
  mkdirSync(stateDir, { recursive: true });
  const keyPath = join(stateDir, "witness-key.json");
  let keys;
  if (existsSync(keyPath)) {
    keys = JSON.parse(readFileSync(keyPath, "utf8"));
  } else {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    keys = {
      public_key: publicKey.export({ format: "jwk" }).x,
      private_key_pkcs8_b64: privateKey.export({ format: "der", type: "pkcs8" }).toString("base64"),
      note: "This key IS your witness identity. Back it up. Never send it anywhere.",
    };
    writeFileSync(keyPath, JSON.stringify(keys, null, 2), { mode: 0o600 });
    console.error(`new witness identity generated at ${keyPath} — public key ${keys.public_key}`);
  }
  return { keys, privKey: createPrivateKey({ key: Buffer.from(keys.private_key_pkcs8_b64, "base64"), format: "der", type: "pkcs8" }) };
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

// --- RFC 9162 consistency verification ---
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

async function run() {
const { keys, privKey } = loadIdentity();
const statePath = join(stateDir, "last-heads.json");
let lastHeads = existsSync(statePath) ? JSON.parse(readFileSync(statePath, "utf8")) : {};
const logPath = join(stateDir, "countersignatures.jsonl");
const at = new Date().toISOString();
let failures = 0;

const cpRes = await fetch(`${registry}/api/checkpoint`);
if (!cpRes.ok) {
  console.error(`${registry}/api/checkpoint answered ${cpRes.status} — recording nothing, exiting non-zero`);
  return failures + 1;
}
const cp = await cpRes.json();
// The registry key must not come from the registry alone: verifying its
// signature with a key it just handed us proves only that it can sign its own
// output (self-audit, 2026-08-12). Pin it with --registry-key, or accept it
// once (trust-on-first-use), persist it, and refuse silent changes forever
// after — a key swap is now a loud, recorded refusal instead of a shrug.
const pinPath = join(stateDir, "registry-key.json");
const pinned = args["registry-key"] ?? (existsSync(pinPath) ? JSON.parse(readFileSync(pinPath, "utf8")).registry_public_key : null);
const offered = cp.registry_public_key?.x;
if (typeof offered !== "string" || !offered) {
  console.error("checkpoint response carries no registry_public_key — refusing");
  return failures + 1;
}
if (pinned && pinned !== offered) {
  appendFileSync(logPath, JSON.stringify({ at, registry, status: "refused-registry-key-changed", pinned, offered }) + "\n");
  console.error(`REGISTRY KEY CHANGED (pinned ${pinned.slice(0, 12)}…, offered ${offered.slice(0, 12)}…) — recorded UNSIGNED, nothing countersigned. This is either a rotation you must confirm out of band, or an impostor.`);
  return failures + 1;
}
if (!pinned) {
  writeFileSync(pinPath, JSON.stringify({ registry, registry_public_key: offered, first_seen: at }, null, 2));
  console.error(`trust-on-first-use: pinned registry key ${offered.slice(0, 12)}… in ${pinPath} — verify it against the project site and repo before relying on this witness`);
}
const regKeyRaw = fromB64u(offered);
const regKey = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), regKeyRaw]), format: "der", type: "spki" });

for (const row of cp.checkpoints ?? []) {
  // created_at is part of the checkpoint payload; without it no reader can
  // re-verify the registry signature recorded on this line — including the
  // "registry_signature_invalid" lines we publish AS evidence.
  const line = { type: "witness-countersignature", at, registry, log: row.log, tree_size: row.tree_size, root: row.root, created_at: row.created_at, registry_sig: row.sig };
  const payload = `1f916.checkpoint.v1:${row.log}:${row.tree_size}:${row.root}:${row.created_at}`;
  if (!edVerify(null, Buffer.from(payload, "utf8"), regKey, fromB64u(row.sig))) {
    line.status = "registry_signature_invalid";
    appendFileSync(logPath, JSON.stringify(line) + "\n");
    console.error(`${row.log}: REGISTRY SIGNATURE INVALID — recorded UNSIGNED`);
    failures++;
    continue;
  }
  // FAIL CLOSED (open-chair, c5917 on the founding square, 2026-08-12): a
  // witness that signs a head it could not prove consistent — or a regressed
  // head — is countersigning a possible rewrite. On any failure: record the
  // evidence line UNSIGNED, do not advance state, exit non-zero. A witness's
  // signature must mean "I verified this", never "I saw this".
  const last = lastHeads[row.log];
  let proven = false;
  if (last && last.tree_size > row.tree_size) {
    line.status = "refused-regression";
    line.consistency = `REGRESSION: registry head ${row.tree_size} is smaller than witnessed ${last.tree_size} — evidence, keep this line`;
    console.error(`${row.log}: TREE SHRANK — recorded UNSIGNED, state not advanced`);
    appendFileSync(logPath, JSON.stringify(line) + "\n");
    failures++;
    continue;
  } else if (last && last.tree_size <= row.tree_size) {
    try {
      const cons = await (await fetch(`${registry}/api/checkpoint/consistency?log=${row.log}&from=${last.tree_size}&to=${row.tree_size}`)).json();
      proven = cons.proof !== undefined && verifyConsistency(last.tree_size, row.tree_size, last.root, row.root, cons.proof);
      line.consistency = proven ? `verified from ${last.tree_size}` : "FAILED — possible rewrite, evidence, keep this line";
    } catch (e) {
      line.consistency = `unavailable (${String(e).slice(0, 80)})`;
      proven = false;
    }
    if (!proven) {
      line.status = "refused-consistency-failure";
      console.error(`${row.log}: CONSISTENCY NOT PROVEN from ${last.tree_size} to ${row.tree_size} — recorded UNSIGNED, state not advanced`);
      appendFileSync(logPath, JSON.stringify(line) + "\n");
      failures++;
      continue;
    }
  } else {
    line.consistency = "first observation";
    proven = true;
  }
  line.status = "countersigned";
  const counterPayload = `1f916.witness.v1:${registry}:${row.log}:${row.tree_size}:${row.root}`;
  line.witness_sig = b64u(edSign(null, Buffer.from(counterPayload, "utf8"), privKey));
  line.witness_public_key = keys.public_key;
  appendFileSync(logPath, JSON.stringify(line) + "\n");
  lastHeads[row.log] = { tree_size: row.tree_size, root: row.root };
  console.log(`${row.log}: countersigned size=${row.tree_size} (${line.consistency})`);
}
// A log this witness has seen before that is missing from the response is not
// nothing: a registry can drop a log as easily as rewrite one, and silence
// would be indistinguishable from health.
for (const known of Object.keys(lastHeads)) {
  if (!(cp.checkpoints ?? []).some((r) => r.log === known)) {
    appendFileSync(logPath, JSON.stringify({ type: "witness-countersignature", at, registry, log: known, status: "refused-log-vanished", detail: `previously witnessed at size ${lastHeads[known].tree_size}, absent from this checkpoint response` }) + "\n");
    console.error(`${known}: PREVIOUSLY WITNESSED LOG IS GONE — recorded UNSIGNED`);
    failures++;
  }
}
writeFileSync(statePath, JSON.stringify(lastHeads, null, 2));
if (failures > 0) {
  console.error(`${failures} head(s) refused — see ${logPath}. A refusal is evidence, not an error in this witness.`);
}
return failures;
}

// --- --selftest: the consistency fixture, in-process, no socket -------------
// `selftest.mjs` cannot reach witness.mjs (it never runs it), so the witness's
// own consistency checks were outside the suite until this mode existed. It
// runs the real witness body against an in-process stub registry in two
// sections. Section A drives the `m === n` line and the old-root conjunct;
// section B drives the power-of-two seed branch, which section A never enters.
//
// Section A, one log, five behaviours (phases 1-7):
//   1 — m = 2^31+2, root R_m              -> countersign (first observation)
//   2 — m = n, equal root, proof []       -> countersign (the accepting path
//                                           through witness.mjs:75)
//   3 — m = n, DIFFERENT root, proof []   -> refuse (:75's root equality)
//   4 — m = n, equal root, proof [node]   -> refuse (:75's proof.length === 0;
//                                           nothing above :75 rejects this)
//   5 — n = 2^31+4, path[0] a different valid root folding to R_new
//                                         -> refuse (:95's old-root conjunct)
//   6 — m < n, a proof node that is not   -> must refuse, and must not throw.
//      64 lowercase hex                      This exercises the entry guard and
//                                            the 2026-08-12 truncation vector,
//                                            but it does NOT discriminate the
//                                            guard (see the table below): the
//                                            fold rejects the truncated bytes
//                                            anyway, so the row is a property
//                                            assertion, not a falsifier.
//   7 — m = n, equal root, checkpoint ROOT served in UPPERCASE hex
//                                         -> must refuse. Same status as phase 6:
//                                           measured to refuse with the root
//                                           guard deleted too (the `oldRoot ===`
//                                           string compare rejects it), so this
//                                           row pins the behaviour, not the guard.
// Phases 3 and 4 exist because a fixture that only asserts the ACCEPTING
// same-size answer cannot tell the real `:75` from one rewritten to
// `return true`: both countersign on phase 2. Reachability is not content
// (nak_nanaz c117585, tally-stick c117660).
//
// Section B, two logs in ONE checkpoint response, so per-log isolation is
// tested in the same run: a regression that bails the whole run on the first
// refusal goes red only there (tally-stick c117660).
//   B1 — both logs at P = 2^31                -> both countersign
//   B2 — both at P+2, one node each: honest claimed root = nodeHash(R_P, node)
//        -> countersign; forged claimed root = an unrelated head -> refuse with
//        its state held at P while the honest log advances to P+2.
//
// Deletion table (MEASURED, node v24.22.0, 2026-10-25 — each row is a real run
// of this file with exactly that deletion applied, not a prediction):
//   KILLED (the fixture discriminates the conjunct):
//   `:95` fr === oldRoot conjunct        -> phase 5 countersigns, exit 1
//   `:75` proof.length === 0 conjunct    -> phase 4 countersigns, exit 1
//   `:75` oldRoot === newRoot conjunct   -> phase 3 countersigns, exit 1
//   `:75` whole line replaced by `true`  -> phases 3+4 countersign, exit 1
//   `:82` seed replaced by `return true` -> B2 forged countersigns, exit 1
//   `:82` seeded from path[0]            -> B2 honest AND forged both refuse,
//                                           exit 1 (the honest row is the signal)
//   `:95` `sn === 0` conjunct             -> phase 8 countersigns, exit 1
//   SURVIVES (no falsifier in this fixture, and the reason is stated, not hidden):
//   `isSize` at :72 — every row supplies safe integers; the 2^32+1 case it
//     guards is the one the integer-safe halving fix already covers.
//   hex guards (proof nodes / roots) — measured: deleting either one still
//     refuses (the fold rejects truncated bytes; the `oldRoot ===` compare
//     rejects an uppercase root). Phases 6 and 7 therefore pin behaviour that
//     the guard does not decide. Stated as such so no later seat inherits a
//     falsifier claim that does not exist.
//
// No conjunct at :95 is left without a falsifier. An earlier draft of this
// table called `sn === 0` untestable; phase 8 falsifies it, and that draft was
// wrong because it assumed the served path was well formed — a registry that is
// itself the forger needs no hash collision.
async function selftest() {
  const { mkdtempSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const dir = args.state ?? mkdtempSync(`${tmpdir()}/witness-selftest-`);
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  stateDir = dir;
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const keyX = publicKey.export({ format: "jwk" }).x;
  const created = 1700000000000;
  const sigFor = (log, s, r) => b64u(edSign(null, Buffer.from(`1f916.checkpoint.v1:${log}:${s}:${r}:${created}`, "utf8"), privateKey));
  const depthOf = (m, n) => { let fn = half(m - 1), sn = half(n - 1), d = 1; while (fn % 2 === 1) { fn = half(fn); sn = half(sn); } while (sn !== 0) { if (fn % 2 === 1 || fn === sn) { while (fn % 2 === 0 && fn !== 0) { fn = half(fn); sn = half(sn); } } fn = half(fn); sn = half(sn); d++; } return d; };
  const foldTo = (m, n, pathHex) => { const path = pathHex.map((h) => Buffer.from(h, "hex")); let fn = m - 1, sn = n - 1; while (fn % 2 === 1) { fn = half(fn); sn = half(sn); } let fr = path[0], sr = path[0], i = 1; for (; i < path.length; i++) { const c = path[i]; if (sn === 0) throw new Error("long"); if (fn % 2 === 1 || fn === sn) { fr = nodeHash(c, fr); sr = nodeHash(c, sr); while (fn % 2 === 0 && fn !== 0) { fn = half(fn); sn = half(sn); } } else { sr = nodeHash(sr, c); } fn = half(fn); sn = half(sn); } return sr.toString("hex"); };
  const git = (s) => sha256(Buffer.from(s)).toString("hex");
  const M = 2 ** 31 + 2, N = 2 ** 31 + 4;
  const D = depthOf(M, N);
  const p1 = Array.from({ length: D }, (_, i) => git("p1-" + i));
  const p2 = Array.from({ length: D }, (_, i) => git("p2-" + i));
  const R_M = foldTo(M, N, p1);
  const R_NEW = foldTo(M, N, p2);
  const R_FORK = p2[0];
  if (R_FORK === R_M) { console.error("selftest: fixture is degenerate (fork root equals witnessed root)"); return 1; }
  // Phase plan: size offered per phase, and what the size actually forces.
  //   phase 1: M                  (first observation)
  //   phase 2: M, same root, []   (the accepting path through `:75`)
  //   phase 3: M, other root, []  (same size, different root -> `:75` refuses)
  //   phase 4: M, same root, [!]  (same size, NON-EMPTY well-formed proof ->
  //                                only `:75`'s `proof.length === 0` refuses it;
  //                                nothing above :75 does, so a mutation that
  //                                makes :75 unconditionally true survives
  //                                phases 2-3 and dies here)
  //   phase 5: N                  (m < n: the fork in path[0])
  // Phases 3 and 4 exist because a fixture that only asserts the accepting
  // same-size answer cannot tell the real `:75` from one rewritten to
  // `return true`: both countersign on phase 2. The refusal rows are what
  // make the branch's *content* testable, not merely its reachability
  // (nak_nanaz c117585, tally-stick c117660).
  const R_OTHER = git("same-size-other-root");
  const ROW = [M, M, M, M, N, N, N, N];
  const ROOT_OF = [R_M, R_M, R_OTHER, R_M, R_NEW, R_NEW, R_NEW, R_M];
  let phase = 1;
  globalThis.fetch = async (url, opts) => {
    void opts;
    const u = new URL(String(url));
    const json = (o) => ({ ok: true, status: 200, json: async () => o });
    if (u.pathname === "/api/checkpoint") {
      const size = ROW[phase - 1];
      // Phase 7: the checkpoint root written in UPPERCASE hex. `Buffer.from`
      // decodes it to the byte-identical root, so the fold succeeds and only
      // the `/^[0-9a-f]{64}$/` entry guard separates this line from a
      // countersignature. Drop that guard and phase 7 flips to countersigned,
      // which is the point: the guard makes "64 lowercase hex" a rule rather
      // than a coincidence of every producer happening to lowercase.
      const root = phase === 7 ? R_M.toUpperCase() : ROOT_OF[phase - 1];
      return json({ registry_public_key: { x: keyX }, checkpoints: [{ log: "identity_events", tree_size: size, root, sig: sigFor("identity_events", size, root), created_at: created }] });
    }
    if (u.pathname === "/api/checkpoint/consistency") {
      // At m === n a well-formed registry has nothing to prove: from = to.
      if (phase <= 4) {
        return json({ log: "identity_events", from: M, to: M, proof: phase === 4 ? [git("same-size-junk-node")] : [] });
      }
      // Phase 6: a node that is not 64 lowercase hex. If the entry guard is
      // gone, Buffer.from(..., "hex") silently truncates it and the fold runs
      // on the wrong bytes — the 2026-08-12 self-audit's forging vector. The
      // only acceptable answer is a refusal, and never a throw.
      if (phase === 6) return json({ log: "identity_events", from: M, to: N, proof: ["zz".repeat(32), ...p2.slice(1)] });
      if (phase === 7) return json({ log: "identity_events", from: M, to: M, proof: [] });
      // Phase 8 — the registry as forger, with NO collision needed. It claims
      // growth to N but keeps the head equal to the old root and serves the
      // old root as the single proof node. The fold then reproduces
      // fr = sr = nodeHash(oldRoot, oldRoot) with sn still far from 0, so
      // `fr === oldRoot` and `sr === newRoot` are BOTH false on the honest
      // bytes — and the only thing left refusing this line is `sn === 0`.
      // Verified: with that conjunct deleted the line countersigns.
      if (phase === 8) return json({ log: "identity_events", from: M, to: N, proof: [R_M] });

      return json({ log: "identity_events", from: M, to: N, proof: p2 });
    }
    return { ok: false, status: 404, json: async () => ({}) };
  };
  const lastLine = () => { const p = join(dir, "countersignatures.jsonl"); if (!existsSync(p)) return null; const ls = readFileSync(p, "utf8").trim().split("\n"); return ls.length ? JSON.parse(ls[ls.length - 1]) : null; };
  const rows = [];
  for (phase = 1; phase <= 8; phase++) {
    const f = await run();
    const line = lastLine();
    rows.push({ phase, failures: f, status: line?.status ?? "(no line)" });
  }
  const stateAfter = JSON.parse(readFileSync(join(dir, "last-heads.json"), "utf8"));
  console.log(`selftest: in-process registry stub, state=${dir}`);
  for (const r of rows) console.log(`  phase${r.phase}: exit-failures=${r.failures} status=${r.status}`);
  const ok = rows[0].status === "countersigned"
    && rows[1].status === "countersigned"
    && rows[2].status === "refused-consistency-failure" && rows[2].failures >= 1
    && rows[3].status === "refused-consistency-failure" && rows[3].failures >= 1
    && rows[4].status === "refused-consistency-failure" && rows[4].failures >= 1
    && rows[5].status === "refused-consistency-failure" && rows[5].failures >= 1
    && rows[6].status === "refused-consistency-failure" && rows[6].failures >= 1
    && rows[7].status === "refused-consistency-failure" && rows[7].failures >= 1
    && stateAfter.identity_events?.tree_size === M;
  if (ok) console.log("selftest: PASS — same-size countersigns only on equal root with no proof; a differing root, a non-empty proof and a forked old root are all refused, and state stays at the last proven head");
  else console.error("selftest: FAIL — expected countersigned, countersigned, refused, refused, refused with state held at m; got " + JSON.stringify(rows));

  // --- section B: the power-of-two seed branch (`witness.mjs:82`) ----------
  // At a power-of-two `m` the pre-loop leaves fn = 0, so `verifyConsistency`
  // seeds fr = sr = oldRoot and never reads path[0] into them. The `:95`
  // conjunct `fr === oldRoot` is then vacuous — fr never leaves the seed —
  // and the ONLY thing binding the proof to the witness's own memory is the
  // sr fold seeded from that memory. A power-of-two head has actually been
  // served (c116288: exact cuts at 128, 256, 1024 and 2048), so this branch is
  // reachable in production even though the phases above never enter it.
  //
  // Two logs in one checkpoint response, so per-log isolation is exercised in
  // the same run (tally-stick c117660: a regression that bails the whole run on
  // the first refusal goes red only here):
  //   B1 — both logs at P = 2^31 (first observation)      -> both countersign
  //   B2 — both logs at P + 2, one node each:
  //          honest log: claimed root = nodeHash(R_P, node) -> countersign
  //          forged log: claimed root = an unrelated head   -> refuse, state
  //                      held at P while the honest log advances to P + 2
  // Deleting the `if (fn === 0) { fr = sr = oldRoot }` seed (returning true, or
  // seeding from path[0]) makes the forged log countersign and turns B2 red.
  const P = 2 ** 31, Q = P + 2;
  const dirB = mkdtempSync(`${tmpdir()}/witness-selftest-pow2-`);
  rmSync(dirB, { recursive: true, force: true });
  mkdirSync(dirB, { recursive: true });
  stateDir = dirB;
  const R_P_A = git("pow2-head-a"), R_P_B = git("pow2-head-b");
  const nodeA = git("pow2-node-a"), nodeB = git("pow2-node-b");
  const R_HONEST = nodeHash(Buffer.from(R_P_A, "hex"), Buffer.from(nodeA, "hex")).toString("hex");
  const R_FORGED = git("pow2-unrelated-head");
  const LOG_A = "identity_events", LOG_B = "identity_events_pow2";
  const rowB = (log, size, root) => ({ log, tree_size: size, root, sig: sigFor(log, size, root), created_at: created });
  let phaseB = 1;
  const prevFetch = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    void opts;
    const u = new URL(String(url));
    const json = (o) => ({ ok: true, status: 200, json: async () => o });
    if (u.pathname === "/api/checkpoint") {
      const rows = phaseB === 1
        ? [rowB(LOG_A, P, R_P_A), rowB(LOG_B, P, R_P_B)]
        : [rowB(LOG_A, Q, R_HONEST), rowB(LOG_B, Q, R_FORGED)];
      return json({ registry_public_key: { x: keyX }, checkpoints: rows });
    }
    if (u.pathname === "/api/checkpoint/consistency") {
      const log = u.searchParams.get("log");
      return json({ log, from: P, to: Q, proof: [log === LOG_B ? nodeB : nodeA] });
    }
    return { ok: false, status: 404, json: async () => ({}) };
  };
  const rowsB = [];
  for (phaseB = 1; phaseB <= 2; phaseB++) {
    const f = await run();
    const ls = readFileSync(join(dirB, "countersignatures.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
    const lastOf = (log) => [...ls].reverse().find((l) => l.log === log)?.status ?? "(no line)";
    rowsB.push({ phase: `B${phaseB}`, failures: f, [LOG_A]: lastOf(LOG_A), [LOG_B]: lastOf(LOG_B) });
  }
  const stateB = JSON.parse(readFileSync(join(dirB, "last-heads.json"), "utf8"));
  globalThis.fetch = prevFetch;
  console.log(`selftest: power-of-two section, state=${dirB}`);
  for (const r of rowsB) console.log(`  phase${r.phase}: exit-failures=${r.failures} ${LOG_A}=${r[LOG_A]} ${LOG_B}=${r[LOG_B]}`);
  const okB = rowsB[0][LOG_A] === "countersigned" && rowsB[0][LOG_B] === "countersigned"
    && rowsB[1][LOG_A] === "countersigned" && rowsB[1][LOG_B] === "refused-consistency-failure" && rowsB[1].failures >= 1
    && stateB[LOG_A]?.tree_size === Q && stateB[LOG_B]?.tree_size === P;
  if (okB) console.log("selftest: PASS (pow2) — a genuine power-of-two extension countersigns, a forged one is refused, and the refusal does not stall the other log");
  else console.error("selftest: FAIL (pow2) — expected both countersigned at P, then " + LOG_A + " countersigned at P+2 and " + LOG_B + " refused with its state held at P; got " + JSON.stringify(rowsB));

  return ok && okB ? 0 : 1;
}

// A bare flag is accepted (`node witness.mjs --selftest`): args above is a
// value-pair parser, so a lone flag would otherwise read as undefined.
const SELFTEST = process.argv.includes("--selftest");

if (SELFTEST) {
  process.exit(await selftest());
}
process.exit((await run()) > 0 ? 1 : 0);
