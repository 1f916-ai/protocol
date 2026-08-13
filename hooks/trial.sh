#!/usr/bin/env bash
# Trial run for the 1F916-Citizen commit-msg hook. Builds a throwaway repo,
# exercises the cases that break attribution conventions in practice, and
# prints PASS/FAIL per case. Exits non-zero if any case fails.
set -u
HOOK="$(cd "$(dirname "$0")" && pwd)/commit-msg"
TMP="$(mktemp -d)"
bad=0

ok() { if [ "$2" = "$3" ]; then echo "PASS  $1"; else echo "FAIL  $1"; echo "        expected: $3"; echo "        got     : $2"; bad=$((bad+1)); fi; }

cd "$TMP"
git init -q . && git config user.email t@example.invalid && git config user.name Trial
git config core.autocrlf false
mkdir -p .git/hooks && cp "$HOOK" .git/hooks/commit-msg && chmod +x .git/hooks/commit-msg

trailer_of() { git log -1 --pretty=%B | grep -ci '^1F916-Citizen:' || true; }
value_of()   { git log -1 --pretty=%B | sed -n 's/^1F916-Citizen: //p'; }

# 1. unconfigured -> no trailer, commit still succeeds
echo a > a.txt && git add -A && git commit -qm "first" 2>/dev/null
ok "1 unconfigured adds nothing"            "$(trailer_of)" "0"
ok "1b unconfigured still commits"          "$(git log --oneline | wc -l | tr -d ' ')" "1"

# 2. configured handle only
git config 1f916.handle Asimovs_Revenge
echo b > b.txt && git add -A && git commit -qm "second"
ok "2 handle-only trailer added"            "$(value_of)" "Asimovs_Revenge"

# 3. handle + id
git config 1f916.citizen 132
echo c > c.txt && git add -A && git commit -qm "third"
ok "3 handle and id"                        "$(value_of)" "Asimovs_Revenge #132"

# 4. amend must not duplicate
git commit -q --amend -m "third amended"
ok "4 amend does not duplicate"             "$(trailer_of)" "1"

# 5. lands inside an existing trailer block, not orphaned
echo d > d.txt && git add -A
git commit -q -m "fourth" -m "Co-Authored-By: Someone <s@example.invalid>"
ok "5a coexists with Co-Authored-By"        "$(trailer_of)" "1"
ok "5b both trailers in one block"          "$(git log -1 --pretty=%B | grep -c -e '^Co-Authored-By:' -e '^1F916-Citizen:')" "2"
ok "5c no blank line between trailers"      "$(git log -1 --pretty=%B | grep -A1 '^Co-Authored-By:' | grep -c '^$')" "0"

# 6. the numero sign, round-tripped through config -> hook -> object store
git config 1f916.citizen "№132"
echo e > e.txt && git add -A && git commit -qm "fifth"
ok "6 U+2116 survives git round-trip"       "$(value_of)" "Asimovs_Revenge #№132"
git config 1f916.citizen 132

# 7. a message that already carries the trailer by hand
echo f > f.txt && git add -A
git commit -q -m "sixth" -m "1F916-Citizen: someone-else #9"
ok "7 hand-written trailer preserved"       "$(value_of)" "someone-else #9"
ok "7b not doubled"                         "$(trailer_of)" "1"

# 8. it is findable the way the proposal claims.
# Five commits carry this handle by now: second, third-amended, fourth, fifth
# (the U+2116 one), seventh. "first" has no trailer and "sixth" names someone else.
echo g > g.txt && git add -A && git commit -qm "seventh"
ok "8 git log --grep finds it"              "$(git log --grep='^1F916-Citizen: Asimovs_Revenge' --pretty=%h | wc -l | tr -d ' ')" "5"
ok "8b grep excludes the other citizen"     "$(git log --grep='^1F916-Citizen: someone-else' --pretty=%h | wc -l | tr -d ' ')" "1"

# 9. merge commit
git checkout -qb side && echo h > h.txt && git add -A && git commit -qm "on side"
git checkout -q - && git merge -q --no-ff side -m "merge side" 2>/dev/null
ok "9 merge commit carries it"              "$(trailer_of)" "1"

echo
if [ "$bad" -eq 0 ]; then echo "ALL CASES PASS"; else echo "$bad CASE(S) FAILED"; fi
cd / && rm -rf "$TMP"
exit "$bad"
