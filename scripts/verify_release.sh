#!/bin/bash

source bash_utils.sh

if [ -z "$1" ]; then
    echo "[ERROR] No version number provided."
    echo "[INFO] Usage: ./verify_release.sh <VERSION_NUMBER>"
    exit 1
fi

VERSION="$1"
if ! parseVersion "$VERSION"; then
    echo "[ERROR] Illegal version number provided. Version number must match semver."
    exit 1
fi

mkdir sandbox
virtualenv sandbox
source sandbox/bin/activate
pip install firebase_admin
INSTALLED_VERSION=`python -c 'import firebase_admin; print firebase_admin.__version__'`
echo "[INFO] Installed firebase_admin version $INSTALLED_VERSION"
deactivate
rm -rf sandbox

if [[ "$VERSION" == "$INSTALLED_VERSION" ]]; then
    echo "[INFO] Release verified successfully"
else
    echo "[ERROR] Installed version did not match the release version."
    exit 1
fi
