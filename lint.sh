#!/bin/bash

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

function lintAllFiles () {
  echo "Running linter on module $1"
  pylint --disable=$2 $1
}

function lintChangedFiles () {
  files=`git status -s $1 | (grep -v "^D") | awk '{print $NF}' | (grep .py$ || true)`
  for f in $files
  do
    echo "Running linter on $f"
    pylint --disable=$2 $f
  done
}

set -o errexit
set -o nounset

SKIP_FOR_TESTS="redefined-outer-name,protected-access,missing-docstring,too-many-lines,len-as-condition"
SKIP_FOR_SNIPPETS="${SKIP_FOR_TESTS},reimported,unused-variable,unused-import,import-outside-toplevel"

if [[ "$#" -eq 1 && "$1" = "all" ]]
then
  CHECK_ALL=true
elif [[ "$#" -eq  0 ]]
then
  CHECK_ALL=false
else
  echo "Usage: ./lint.sh [all]"
  exit 1
fi

if [[ "$CHECK_ALL" = true ]]
then
  lintAllFiles "firebase_admin" ""
  lintAllFiles "tests" "$SKIP_FOR_TESTS"
  lintAllFiles "integration" "$SKIP_FOR_TESTS"
  lintAllFiles "snippets" "$SKIP_FOR_SNIPPETS"
else
  lintChangedFiles "firebase_admin" ""
  lintChangedFiles "tests" "$SKIP_FOR_TESTS"
  lintChangedFiles "integration" "$SKIP_FOR_TESTS"
  lintChangedFiles "snippets" "$SKIP_FOR_SNIPPETS"
fi
