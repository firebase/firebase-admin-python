#!/bin/bash
# Shell script to seed the Firebase Data Connect emulator with initial test data.
set -e

EMULATOR_HOST="${DATA_CONNECT_EMULATOR_HOST:-127.0.0.1:9399}"
ENDPOINT="http://${EMULATOR_HOST}/v1/projects/test-project/locations/us-west2/services/my-service:executeGraphql"

echo "Seeding Data Connect emulator at ${ENDPOINT}..."

# 1. Seed Fred User
curl -s -f -X POST "${ENDPOINT}" \
  -H "Authorization: Bearer owner" \
  -H "Content-Type: application/json" \
  -d '{"query": "mutation { user_upsert(data: { id: \"fred_id\", address: \"32 Elm St.\", name: \"Fred\" }) }"}' > /dev/null

# 2. Seed Jeff User
curl -s -f -X POST "${ENDPOINT}" \
  -H "Authorization: Bearer owner" \
  -H "Content-Type: application/json" \
  -d '{"query": "mutation { user_upsert(data: { id: \"jeff_id\", address: \"99 Oak St.\", name: \"Jeff\" }) }"}' > /dev/null

# 3. Seed Fred Email
curl -s -f -X POST "${ENDPOINT}" \
  -H "Authorization: Bearer owner" \
  -H "Content-Type: application/json" \
  -d '{"query": "mutation { email_upsert(data: { id: \"email_id\", subject: \"free bitcoin inside\", date: \"1999-12-31\", text: \"get pranked! LOL!\", fromId: \"fred_id\" }) }"}' > /dev/null

echo "Successfully seeded initial test data (2 users, 1 email)!"
