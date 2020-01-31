#!/bin/bash

set -e
set -u

function printChangelog() {
  local TITLE=$1
  shift
  local ENTRIES=("$@")
  if [ ${#ENTRIES[@]} -ne 0 ]; then
    echo "### ${TITLE}"
    echo ""
    for ((i = 0; i < ${#ENTRIES[@]}; i++))
    do
        echo "* ${ENTRIES[$i]}"
    done
    echo ""
  fi
}

if [[ -z "${GITHUB_SHA}" ]]; then
  GITHUB_SHA="HEAD"
fi

LAST_TAG=`git describe --tags $(git rev-list --tags --max-count=1) 2> /dev/null` || true
if [[ -z "${LAST_TAG}" ]]; then
  echo "[info] No tags found. Including all commits up to ${GITHUB_SHA}."
  VERSION_RANGE="${GITHUB_SHA}"
else
  echo "[info] Last release tag: ${LAST_TAG}."
  COMMIT_SHA=`git show-ref -s ${LAST_TAG}`
  echo "[info] Last release commit: ${COMMIT_SHA}."
  VERSION_RANGE="${COMMIT_SHA}..${GITHUB_SHA}"
  echo "[info] Including all commits in the range ${VERSION_RANGE}."
fi

echo ""
CHANGES=()
FIXES=()
FEATS=()
MISC=()

while read -r line
do
  COMMIT_MSG=`echo ${line} | cut -d ' ' -f 2-`
  if [[ $COMMIT_MSG =~ ^change(\(.*\))?: ]]; then
    CHANGES+=("$COMMIT_MSG")
  elif [[ $COMMIT_MSG =~ ^fix(\(.*\))?: ]]; then
    FIXES+=("$COMMIT_MSG")
  elif [[ $COMMIT_MSG =~ ^feat(\(.*\))?: ]]; then
    FEATS+=("$COMMIT_MSG")
  else
    MISC+=("${COMMIT_MSG}")
  fi
done < <(git log ${VERSION_RANGE} --oneline)

printChangelog "Breaking Changes" "${CHANGES[@]}"
printChangelog "New Features" "${FEATS[@]}"
printChangelog "Bug Fixes" "${FIXES[@]}"
printChangelog "Miscellaneous" "${MISC[@]}"
