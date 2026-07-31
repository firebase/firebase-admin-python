#!/bin/bash
# Shell script to seed the Firebase Data Connect emulator with initial test data.
set -e

EMULATOR_HOST="${DATA_CONNECT_EMULATOR_HOST:-127.0.0.1:9399}"
ENDPOINT="http://${EMULATOR_HOST}/v1/projects/test-project/locations/us-west2/services/my-service:executeGraphql"

echo "Seeding Data Connect emulator at ${ENDPOINT}..."

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

  # Check if response contains non-empty GraphQL errors using python JSON parser
  if ! python3 -c "import sys, json; d=json.loads(sys.argv[1]); sys.exit(0 if not d.get('errors') else 1)" "${response}"; then
    echo "GraphQL error seeding data with payload ${payload}: ${response}" >&2
    exit 1
  fi
}

# 1. Seed Fred User
send_gql_mutation '{"query": "mutation { user_upsert(data: { id: \"fred_id\", address: \"32 Elm St.\", name: \"Fred\" }) }"}'

# 2. Seed Jeff User
send_gql_mutation '{"query": "mutation { user_upsert(data: { id: \"jeff_id\", address: \"99 Oak St.\", name: \"Jeff\" }) }"}'

# 3. Seed Fred Email
send_gql_mutation '{"query": "mutation { email_upsert(data: { id: \"email_id\", subject: \"free bitcoin inside\", date: \"1999-12-31\", text: \"get pranked! LOL!\", fromId: \"fred_id\" }) }"}'

echo "Successfully seeded initial test data (2 users, 1 email)!"
