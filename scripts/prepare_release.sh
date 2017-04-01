#!/bin/bash

function parseVersion {
    if [[ ! "$1" =~ ^([0-9]*)\.([0-9]*)\.([0-9]*)$ ]]; then
        return 1
    fi
    MAJOR_VERSION=$(echo "$1" | sed -e 's/^\([0-9]*\)\.\([0-9]*\)\.\([0-9]*\)$/\1/')
    MINOR_VERSION=$(echo "$1" | sed -e 's/^\([0-9]*\)\.\([0-9]*\)\.\([0-9]*\)$/\2/')
    PATCH_VERSION=$(echo "$1" | sed -e 's/^\([0-9]*\)\.\([0-9]*\)\.\([0-9]*\)$/\3/')
    return 0
}

function isNewerVersion {
    parseVersion "$1"
    ARG_MAJOR=$MAJOR_VERSION
    ARG_MINOR=$MINOR_VERSION
    ARG_PATCH=$PATCH_VERSION

    parseVersion "$2"
    if [ "$ARG_MAJOR" -ne "$MAJOR_VERSION" ]; then
        if [ "$ARG_MAJOR" -lt "$MAJOR_VERSION" ]; then return 1; else return 0; fi;
    fi
    if [ "$ARG_MINOR" -ne "$MINOR_VERSION" ]; then
        if [ "$ARG_MINOR" -lt "$MINOR_VERSION" ]; then return 1; else return 0; fi;
    fi
    if [ "$ARG_PATCH" -ne "$PATCH_VERSION" ]; then
        if [ "$ARG_PATCH" -lt "$PATCH_VERSION" ]; then return 1; else return 0; fi;
    fi
    # The build numbers are equal
    return 1
}

set -e

if [ -z "$1" ]; then
    echo "[ERROR] No version number provided."
    echo "[INFO] Usage: ./prepare_release.sh <VERSION_NUMBER>"
    exit 1
fi

VERSION="$1"
if ! parseVersion "$VERSION"; then
    echo "[ERROR] Illegal version number provided. Version number must match semver."
    exit 1
fi

CUR_VERSION=`grep "^__version__ =" ../firebase_admin/__init__.py | awk '{print $3}' | sed "s/'//g"`
if [ -z "$CUR_VERSION" ]; then
    echo "[ERROR] Failed to find the current version. Check firebase_admin/__init__.py for version declaration."
    exit 1
fi
if ! parseVersion "$CUR_VERSION"; then
    echo "[ERROR] Illegal current version number. Version number must match semver."
    exit 1
fi

if ! isNewerVersion "$VERSION" "$CUR_VERSION"; then
    echo "[ERROR] Illegal version number provided. Version $VERSION <= $CUR_VERSION"
    exit 1
fi

if [[ `git status --porcelain` ]]; then
    echo "[ERROR] Local changes exist in the repo. Resolve local changes before release."
    exit 1
fi


echo "[INFO] Updating version number in firebase_admin/__init__.py"
sed --in-place -e "s/__version__ = '$CUR_VERSION'/__version__ = '$VERSION'/" "../firebase_admin/__init__.py"

echo "[INFO] Running unit tests"
tox --workdir ..

echo "[INFO] This repo has been prepared for a release. Create a branch and commit the changes."
