#!/bin/bash

function lintAllFiles () {
  echo "Running linter on module $1"
  pylint --disable=$2 $1
}

function lintChangedFiles () {
  files=`git status -s $1 | grep -v "^D" | awk '{print $NF}' | grep .py$`
  for f in $files
  do
    echo "Running linter on $f"
    pylint --disable=$2 $f
  done
}

SKIP_FOR_TESTS="redefined-outer-name,protected-access,missing-docstring"

if [[ $1 = "all" ]]
then
  lintAllFiles firebase
  lintAllFiles tests $SKIP_FOR_TESTS
else
  lintChangedFiles firebase
  lintChangedFiles tests $SKIP_FOR_TESTS
fi
