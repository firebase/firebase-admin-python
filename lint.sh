#!/bin/bash

function lintAllFiles () {
  files=`find $1 -name *.py`
  for f in $files
  do
    echo "Running linter on $f"
    pylint --rcfile $2 $f
  done
}

function lintChangedFiles () {
  files=`git status -s $1 | awk '{print $2}' | grep .py$`
  for f in $files
  do
    echo "Running linter on $f"
    pylint --rcfile $2 $f
  done
}

if [[ $1 = "all" ]]
then
  lintAllFiles firebase .pylintrc
  lintAllFiles tests .test_pylintrc
else
  lintChangedFiles firebase .pylintrc
  lintChangedFiles tests .test_pylintrc
fi
