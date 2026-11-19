#!/usr/bin/env bash
# upstream-sync_test.sh -- tests for upstream-sync.sh against local repos.
# Plain bash, no test framework.
# Helpers are called indirectly through check/check_fails.
# shellcheck disable=SC2329
set -euo pipefail

script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/upstream-sync.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.com GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.com
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null

fail=0

# setup: upstream (bare) with master at U1; origin (bare) with master=U1 and
# miriel = U1 + a local commit; work = a clone of origin to run the script in.
setup() {
  rm -rf "${tmp:?}"/*
  git init -q --bare -b master "${tmp}/upstream.git"
  git init -q --bare -b master "${tmp}/origin.git"
  git clone -q "${tmp}/upstream.git" "${tmp}/up" 2>/dev/null
  git -C "${tmp}/up" checkout -q -b master
  git -C "${tmp}/up" commit -q --allow-empty -m U1
  git -C "${tmp}/up" push -q origin master
  git -C "${tmp}/up" push -q "${tmp}/origin.git" master
  git -C "${tmp}/up" checkout -q -b miriel
  git -C "${tmp}/up" commit -q --allow-empty -m fork-change
  git -C "${tmp}/up" push -q "${tmp}/origin.git" miriel
  git -C "${tmp}/up" checkout -q master
  git clone -q "${tmp}/origin.git" "${tmp}/work" 2>/dev/null
}

upstream_commit() { git -C "${tmp}/up" commit -q --allow-empty -m "$1" && git -C "${tmp}/up" push -q origin master; }

# run <dry_run>: prints the output file and returns the script's status.
run() {
  : > "${tmp}/out"
  (cd "${tmp}/work" && UPSTREAM_URL="${tmp}/upstream.git" DRY_RUN="$1" GITHUB_OUTPUT="${tmp}/out" bash "${script}" >"${tmp}/log" 2>&1)
}

# check <label> <command...>: passes when the command succeeds.
check() {
  local label="$1"
  shift
  if "$@"; then
    echo "ok   - ${label}"
  else
    echo "FAIL - ${label}"
    sed 's/^/    /' "${tmp}/log"
    fail=1
  fi
}

# check_fails <label> <command...>: passes when the command fails.
check_fails() {
  local label="$1"
  shift
  if "$@"; then
    echo "FAIL - ${label} (succeeded, want failure)"
    sed 's/^/    /' "${tmp}/log"
    fail=1
  else
    echo "ok   - ${label}"
  fi
}

origin_master() { git -C "${tmp}/origin.git" rev-parse master; }
up_master() { git -C "${tmp}/upstream.git" rev-parse master; }
master_is() { [[ "$(origin_master)" == "$1" ]]; }
out_has() { grep -q "$1" "${tmp}/out"; }
log_has() { grep -q "$1" "${tmp}/log"; }

# 1. master already at upstream, miriel already has it: nothing to do.
setup
check "no-op succeeds" run false
check "no-op needs no PR" out_has '^needs_pr=false$'

# 2. upstream moves: master fast-forwards, PR needed.
upstream_commit U2
check "fast-forward succeeds" run false
check "master was fast-forwarded" master_is "$(up_master)"
check "PR needed after upstream moved" out_has '^needs_pr=true$'
check "one commit missing from miriel" out_has '^ahead=1$'

# 3. master synced earlier but miriel never merged it: still needs a PR.
check "re-run succeeds" run false
check "PR still needed while miriel lacks the commit" out_has '^needs_pr=true$'

# 4. miriel merges master: no PR needed.
git -C "${tmp}/work" fetch -q origin
git -C "${tmp}/work" checkout -q -b miriel origin/miriel
git -C "${tmp}/work" merge -q --no-ff -m merge origin/master
git -C "${tmp}/work" push -q origin miriel
git -C "${tmp}/work" checkout -q master
check "run after merge succeeds" run false
check "no PR once miriel contains master" out_has '^needs_pr=false$'

# 5. dry run does not move master.
upstream_commit U3
before="$(origin_master)"
check "dry run succeeds" run true
check "dry run leaves master alone" master_is "${before}"
check "dry run still reports the PR need" out_has '^needs_pr=true$'

# 6. diverged master: refuse, never rewrite it.
setup
git -C "${tmp}/up" checkout -q -b local-only
git -C "${tmp}/up" commit -q --allow-empty -m local-on-master
git -C "${tmp}/up" push -q "${tmp}/origin.git" local-only:master
upstream_commit U2
before="$(origin_master)"
check_fails "diverged master fails" run false
check "diverged master is untouched" master_is "${before}"
check "diverged master explains itself" log_has "not an ancestor"

exit "${fail}"
