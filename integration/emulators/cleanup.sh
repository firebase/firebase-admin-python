#!/bin/bash
# Shell script to clear all test data from the Firebase Data Connect emulator.
set -e

EMULATOR_HOST="${DATA_CONNECT_EMULATOR_HOST:-127.0.0.1:9399}"
ENDPOINT="http://${EMULATOR_HOST}/v1/projects/test-project/locations/us-west2/services/my-service:executeGraphql"

send_gql_mutation() {
  local payload="$1"
  local response
  response=$(curl -s -X POST "${ENDPOINT}" \
    -H "Authorization: Bearer owner" \
    -H "Content-Type: application/json" \
    -d "${payload}")

  if [ -z "${response}" ]; then
    echo "Failed to receive response from Data Connect emulator at ${ENDPOINT}" >&2
    exit 1
  fi
}

send_gql_mutation '{"query": "mutation { email_deleteMany(all: true) user_deleteMany(all: true) }"}'
