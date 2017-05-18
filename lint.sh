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

function lintAllFiles () {
  echo "Running linter on module $1"
  pylint --disable=$2 $1
  rc=$?
  if [ $rc -ne 0 ]
  then
    exit $rc
  fi
}

function lintChangedFiles () {
  files=`git status -s $1 | grep -v "^D" | awk '{print $NF}' | grep .py$`
  for f in $files
  do
    echo "Running linter on $f"
    pylint --disable=$2 $f
    rc=$?
    if [ $rc -ne 0 ]
    then
      exit $rc
    fi
  done
}

SKIP_FOR_TESTS="redefined-outer-name,protected-access,missing-docstring"

if [[ $1 = "all" ]]
then
  lintAllFiles firebase_admin
  lintAllFiles tests $SKIP_FOR_TESTS
else
  lintChangedFiles firebase_admin
  lintChangedFiles tests $SKIP_FOR_TESTS
fi
