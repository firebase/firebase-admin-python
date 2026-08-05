#!/bin/bash
# Shell script to seed or clean up test data in the Firebase Data Connect emulator or production.
set -e

ACTION="${1:-setup}"

if [ -n "${DATA_CONNECT_EMULATOR_HOST}" ]; then
  ENDPOINT="http://${DATA_CONNECT_EMULATOR_HOST}/v1/projects/test-project/locations/us-west2/services/my-service:executeGraphql"
  AUTH_HEADER="Authorization: Bearer owner"
else
  CERT_FILE="${GOOGLE_APPLICATION_CREDENTIALS:-cert.json}"
  PROJECT_ID="${FB_INTEGRATION_PROJECT_ID:-$(python3 -c "import json, os; print(json.load(open('${CERT_FILE}')).get('project_id', '')) if os.path.exists('${CERT_FILE}') else print('')")}"
  ENDPOINT="https://dataconnect.googleapis.com/v1/projects/${PROJECT_ID}/locations/us-west2/services/my-service:executeGraphql"
  
  ACCESS_TOKEN=$(python3 -c "
import google.auth, google.auth.transport.requests, os
from google.oauth2 import service_account

cert_file = '${CERT_FILE}'
if os.path.exists(cert_file):
    creds = service_account.Credentials.from_service_account_file(cert_file, scopes=['https://www.googleapis.com/auth/cloud-platform'])
else:
    creds, _ = google.auth.default()
    creds = creds.with_scopes(['https://www.googleapis.com/auth/cloud-platform'])

creds.refresh(google.auth.transport.requests.Request())
print(creds.token)
")
  AUTH_HEADER="Authorization: Bearer ${ACCESS_TOKEN}"
fi

send_gql_mutation() {
  local payload="$1"
  local response
  response=$(curl -s -X POST "${ENDPOINT}" \
    -H "${AUTH_HEADER}" \
    -H "Content-Type: application/json" \
    -d "${payload}")

  if [ -z "${response}" ]; then
    echo "Failed to receive response from Data Connect endpoint at ${ENDPOINT}" >&2
    exit 1
  fi

  # Check if response contains non-empty GraphQL errors using python JSON parser
  if ! python3 -c "import sys, json; d=json.loads(sys.argv[1]); sys.exit(0 if not d.get('errors') else 1)" "${response}"; then
    echo "GraphQL error in Data Connect payload ${payload}: ${response}" >&2
    exit 1
  fi
}

if [ "${ACTION}" = "setup" ] || [ "${ACTION}" = "seed" ]; then
  send_gql_mutation '{"query": "mutation { user_upsert(data: { id: \"fred_id\", address: \"32 Elm St.\", name: \"Fred\" }) }"}'
  send_gql_mutation '{"query": "mutation { user_upsert(data: { id: \"jeff_id\", address: \"99 Oak St.\", name: \"Jeff\" }) }"}'
  send_gql_mutation '{"query": "mutation { email_upsert(data: { id: \"email_id\", subject: \"free bitcoin inside\", date: \"1999-12-31\", text: \"get pranked! LOL!\", fromId: \"fred_id\" }) }"}'
elif [ "${ACTION}" = "teardown" ] || [ "${ACTION}" = "cleanup" ]; then
  send_gql_mutation '{"query": "mutation { email_deleteMany(all: true) user_deleteMany(all: true) }"}'
else
  echo "Unknown action: ${ACTION}. Expected 'setup' or 'teardown'." >&2
  exit 1
fi
