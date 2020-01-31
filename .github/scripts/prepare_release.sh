#!/bin/bash

###################################### Outputs #####################################

# 1. version: The version of this release including the 'v' prefix (e.g. v1.2.3).
# 2. publish: Set when not executing in the dryrun mode.
# 3. tweet: Set when the release should be posted to Twitter. Only set when
#    publish=true.
# 4. changelog: Formatted changelog text for this release.

####################################################################################

set -e
set -u

echo "[release:dryrun]: ${DRYRUN_RELEASE}"
echo "[release:skip-tweet]: ${SKIP_TWEET}"
echo ""

# Find release version.
RELEASE_VERSION=`python -c "exec(open('firebase_admin/__about__.py').read()); print(__version__)"` || true
if [[ -z "${RELEASE_VERSION}" ]]; then
  echo "Failed to extract release version from firebase_admin/__about__.py. Exiting."
  exit 1
fi

if [[ ! "${RELEASE_VERSION}" =~ ^([0-9]*)\.([0-9]*)\.([0-9]*)$ ]]; then
  echo "Malformed release version string: ${RELEASE_VERSION}. Exiting."
  exit 1
fi

echo "Extracted release version: ${RELEASE_VERSION}"
echo "::set-output name=version::v${RELEASE_VERSION}"

# Ensure the release version does not already exist in Pypi.
PYPI_URL="https://pypi.org/pypi/firebase-admin/${RELEASE_VERSION}/json"
PYPI_STATUS=`curl -s -o /dev/null -L -w "%{http_code}" ${PYPI_URL}`
if [[ $PYPI_STATUS -eq 404 ]]; then
  echo "Release version not found in Pypi."
elif [[ $PYPI_STATUS -eq 200 ]]; then
  echo "Release version already present in Pypi. Exiting."
  exit 1
else
  echo "Unexpected ${PYPI_STATUS} response from Pypi. Exiting."
  exit 1
fi

# Fetch all tags.
git fetch --depth=1 origin +refs/tags/*:refs/tags/*

# Check if this release is already tagged.
EXISTING_TAG=`git rev-parse -q --verify "refs/tags/v${RELEASE_VERSION}"` || true
if [[ -n "${EXISTING_TAG}" ]]; then
  RELEASE_URL="https://github.com/firebase/firebase-admin-python/releases/tag/v${RELEASE_VERSION}"
  echo "Tag v${RELEASE_VERSION} already exists. Exiting."
  echo "If the tag was created in a previous unsuccessful attempt, delete it and try again."
  echo "Delete any corresponding releases at ${RELEASE_URL}."
  echo "  $ git tag -d v${RELEASE_VERSION}"
  echo "  $ git push --delete origin v${RELEASE_VERSION}"
  exit 1
fi

echo "Tag v${RELEASE_VERSION} does not exist."

# Handle dryrun mode.
if [[ "$DRYRUN_RELEASE" == "true" ]]; then
  echo "Dryrun mode has been requested. No new tags or artifacts will be published."
else
  echo "Dryrun mode has NOT been requested."
  echo "A new tag will be created, and release artifacts posted to Pypi."
  echo "::set-output name=publish::true"

  if [[ "${SKIP_TWEET}" != "true" ]]; then
    echo "Release will be posted to Twitter upon successful completion."
    echo "::set-output name=tweet::true"
  else
    echo "Skip Tweet mode has been requested. Release will not be posted to Twitter."
  fi
fi

# Fetch history of the master branch.
git fetch origin master --prune --unshallow

# Generate changelog from commit history.
echo "Generating changelog from history."
echo ""
CURRENT_DIR=$(dirname "$0")
CHANGELOG=`${CURRENT_DIR}/generate_changelog.sh`
echo "$CHANGELOG"

# Parse and preformat the text to handle multi-line output.
# See https://github.community/t5/GitHub-Actions/set-output-Truncates-Multiline-Strings/td-p/37870
FILTERED_CHANGELOG=`echo "$CHANGELOG" | grep -v "\\[info\\]"`
FILTERED_CHANGELOG="${FILTERED_CHANGELOG//'%'/'%25'}"
FILTERED_CHANGELOG="${FILTERED_CHANGELOG//$'\n'/'%0A'}"
FILTERED_CHANGELOG="${FILTERED_CHANGELOG//$'\r'/'%0D'}"
echo "::set-output name=changelog::${FILTERED_CHANGELOG}"
