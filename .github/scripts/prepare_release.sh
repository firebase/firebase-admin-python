#!/bin/bash

###################################### Outputs #####################################

# 1. version: The version of this release including the 'v' prefix (e.g. v1.2.3).
# 2. publish: Set when not executing in the dryrun mode.
# 3. tweet: Set when the release should be posted to Twitter. Also implies
#    publish=true.
# 4. create_tag: Set when the release is not already tagged.
# 5. reuse_tag: Set when the release is already tagged.
# 6. directory: Directory where the release artifacts will be built. Either
#    'staging' or 'deploy'.

####################################################################################

echo "[release:retry]: ${RETRY_RELEASE}"
echo "[release:dryrun]: ${DRYRUN_RELEASE}"
echo "[release:skip-tweet]: ${SKIP_TWEET}"
echo

# Find current version.
RELEASE_VERSION=`python -c "exec(open('firebase_admin/__about__.py').read()); print(__version__)"`
echo "Releasing version ${RELEASE_VERSION}"
echo "::set-output name=version::v${RELEASE_VERSION}"

# Handle dryrun mode.
if [[ "$DRYRUN_RELEASE" == "true" ]]; then
  echo "Dryrun mode has been requested. No new tags or artifacts will be published."
  DIRECTORY="staging"
else
  echo "Dryrun mode has not been requested. Executing in the publish mode."
  DIRECTORY="deploy"
  echo "::set-output name=publish::true"

  if [[ "${SKIP_TWEET}" != "true" ]]; then
    echo "Release will be posted to Twitter upon successful completion."
    echo "::set-output name=tweet::true"
  else
    echo "Skip Tweet mode has been requested. Release will not be posted to Twitter."
  fi
fi

# Fetch all tags.
git fetch --depth=1 origin +refs/tags/*:refs/tags/*

# Check if this release is already tagged.
git describe --tags v${RELEASE_VERSION} 2> /dev/null

if [[ $? -eq 0 ]]; then
  echo "Tag v${RELEASE_VERSION} already exists."

  if [[ "${RETRY_RELEASE}" != "true" ]]; then
    echo "Retry mode has not been requested. Exiting."
    echo "Label your PR with [release: retry] to build a release from an existing tag."
    exit 1
  fi

  echo "Retry mode has been requested. Releasing from the existing tag."
  echo "::set-output name=reuse_tag::true"

  # When a tag already exists, we will use it to build artifacts even when
  # the dryrun mode is requested.
  DIRECTORY="deploy"
else
  echo "Tag v${RELEASE_VERSION} does not exist."
  echo "::set-output name=create_tag::true"
fi

echo "Release artifacts will be built in the ${DIRECTORY} directory."
echo "::set-output name=directory::${DIRECTORY}"
