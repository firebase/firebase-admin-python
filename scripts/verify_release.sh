# Copyright 2017 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
