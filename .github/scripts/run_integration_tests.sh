#!/bin/bash

set -e
set -u

gpg --quiet --batch --yes --decrypt --passphrase="${FIREBASE_SERVICE_ACCT_KEY}" \
  --output integ-service-account.json .github/resources/integ-service-account.json.gpg

echo "${FIREBASE_API_KEY}" > integ-api-key.txt

pytest integration/ --cert integ-service-account.json --apikey integ-api-key.txt
