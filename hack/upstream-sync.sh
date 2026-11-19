#!/usr/bin/env bash
# upstream-sync.sh -- fast-forward the fork's mirror branch (master) to the
# upstream default branch and report whether the integration branch (miriel)
# is missing upstream commits.
#
# Never force-pushes: the mirror push is a plain fast-forward and fails if
# master has commits upstream does not (a diverged mirror needs a person).
#
# Environment:
#   UPSTREAM_URL   upstream repository URL (required)
#   UPSTREAM_REF   upstream branch to follow            (default: master)
#   MIRROR_BRANCH  fork branch that mirrors it           (default: master)
#   BASE_BRANCH    integration branch that gets the PR   (default: miriel)
#   DRY_RUN        "true" to report without pushing      (default: false)
#   GITHUB_OUTPUT  when set, receives needs_pr, ahead and sha
#
# Exit status is non-zero on any failure, including a rejected push.

set -euo pipefail

: "${UPSTREAM_URL:?UPSTREAM_URL is required}"
UPSTREAM_REF="${UPSTREAM_REF:-master}"
MIRROR_BRANCH="${MIRROR_BRANCH:-master}"
BASE_BRANCH="${BASE_BRANCH:-miriel}"
DRY_RUN="${DRY_RUN:-false}"

git fetch --quiet --no-tags origin \
  "+refs/heads/${MIRROR_BRANCH}:refs/remotes/origin/${MIRROR_BRANCH}" \
  "+refs/heads/${BASE_BRANCH}:refs/remotes/origin/${BASE_BRANCH}"
git fetch --quiet --no-tags "${UPSTREAM_URL}" "+refs/heads/${UPSTREAM_REF}:refs/remotes/upstream/${UPSTREAM_REF}"

mirror="$(git rev-parse "refs/remotes/origin/${MIRROR_BRANCH}")"
upstream="$(git rev-parse "refs/remotes/upstream/${UPSTREAM_REF}")"

if [[ "${mirror}" == "${upstream}" ]]; then
  echo "${MIRROR_BRANCH} is already at upstream ${UPSTREAM_REF} (${upstream:0:12})."
elif git merge-base --is-ancestor "${mirror}" "${upstream}"; then
  echo "Fast-forwarding ${MIRROR_BRANCH} ${mirror:0:12} -> ${upstream:0:12}."
  if [[ "${DRY_RUN}" == "true" ]]; then
    echo "dry run: not pushing."
  else
    # No --force: GitHub refuses anything but a fast-forward here.
    if ! git push origin "${upstream}:refs/heads/${MIRROR_BRANCH}" 2>push.err; then
      cat push.err >&2
      if grep -q "without .workflows. permission" push.err; then
        echo "::error::GITHUB_TOKEN cannot push commits that change .github/workflows/*. Upstream changed workflow files, so ${MIRROR_BRANCH} has to be synced by someone whose credentials carry the workflows permission (for example the Sync fork button)."
      else
        echo "::error::fast-forwarding ${MIRROR_BRANCH} was rejected."
      fi
      exit 1
    fi
    rm -f push.err
  fi
else
  echo "::error::${MIRROR_BRANCH} (${mirror:0:12}) is not an ancestor of upstream ${UPSTREAM_REF} (${upstream:0:12}); it has commits upstream does not. Not touching it; a person has to reconcile it."
  exit 1
fi

# The integration branch needs a PR when it lacks any upstream commit.
ahead="$(git rev-list --count "refs/remotes/origin/${BASE_BRANCH}..${upstream}")"
needs_pr=false
if [[ "${ahead}" -gt 0 ]]; then
  needs_pr=true
fi
echo "${BASE_BRANCH} lacks ${ahead} upstream commit(s); needs_pr=${needs_pr}."

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    echo "needs_pr=${needs_pr}"
    echo "ahead=${ahead}"
    echo "sha=${upstream}"
  } >> "${GITHUB_OUTPUT}"
fi
