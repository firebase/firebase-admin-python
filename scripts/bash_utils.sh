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
