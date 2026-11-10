#!/usr/bin/env node
// Runs the reference verifier verify.mjs against every frozen vector in
// testvectors/corpus/ and checks the verdict and exit status against
// testvectors/expected-verdicts.json. Exits non-zero if any vector drifts.
//
// This is the gate a SECOND, independent verifier runs against too: point your
// implementation at the same corpus/<name>/ inputs and the same args, and your
// verdict + exit status must match expected_verdict / expected_exit for every
// vector. Disagreement is a finding about one of the two implementations or an
// ambiguity in the spec — see testvectors/CONTRACT.md. Run: node testvectors/run-corpus.mjs
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const repo = dirname(here);
const manifest = JSON.parse(readFileSync(join(here, "expected-verdicts.json"), "utf8"));

function run(argv) {
  try {
    return { stdout: execFileSync("node", ["verify.mjs", ...argv], { cwd: repo, encoding: "utf8" }), code: 0 };
  } catch (e) {
    return { stdout: (e.stdout ?? "") + (e.stderr ?? ""), code: e.status ?? -1 };
  }
}

let bad = 0;
for (const v of manifest.vectors) {
  const base = join(here, "corpus", v.name);
  const argv = v.kind === "dossier"
    ? ["--dossier", join(base, v.files.dossier), ...v.args]
    : ["--checkpoint", join(base, v.files.checkpoint), "--witness", join(base, v.files.witness), ...v.args];
  const { stdout, code } = run(argv);
  const got = (stdout.match(/VERDICT: (\S+)/) ?? [])[1];
  const ok = got === v.expected_verdict && code === v.expected_exit;
  if (!ok) { bad++; console.log(`FAIL  ${v.name}: manifest says ${v.expected_verdict}/exit ${v.expected_exit}, got ${got}/exit ${code}`); }
  else console.log(`PASS  ${v.name}: ${got} / exit ${code}`);
}
console.log(`\n${manifest.vectors.length} vectors, ${bad} drifted. spec ${manifest.spec_version}, pinned ${manifest.pinned_commit.slice(0, 12)}.`);
process.exit(bad ? 1 : 0);
