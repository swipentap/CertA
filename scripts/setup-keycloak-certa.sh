#!/usr/bin/env bash
# Setup Keycloak certa realm: assign certa admin role to admin user.
# Run after Keycloak + realm import. Uses certa realm (from keycloak/certa-realm.json).
# Usage: OAUTH2_IDP_BASE_URL=http://localhost:8180 OAUTH2_IDP_REALM=certa OAUTH2_IDP_ADMIN_USER=admin OAUTH2_IDP_ADMIN_PASSWORD=admin OAUTH2_TEST_USER=admin ./scripts/setup-keycloak-certa.sh

set -e

BASE="${OAUTH2_IDP_BASE_URL:-http://localhost:8180}"
REALM="${OAUTH2_IDP_REALM:-certa}"
ADMIN_USER="${OAUTH2_IDP_ADMIN_USER:-admin}"
ADMIN_PASS="${OAUTH2_IDP_ADMIN_PASSWORD:-admin}"
TARGET_USER="${OAUTH2_TEST_USER:-admin}"

echo "Waiting for Keycloak at ${BASE}..."
until curl -sf "${BASE}/realms/${REALM}/.well-known/openid-configuration" > /dev/null 2>&1; do
  sleep 2
done
echo "Keycloak is ready."

echo "Getting admin token..."
TOKEN=$(curl -sf -X POST "${BASE}/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=admin-cli" \
  -d "username=${ADMIN_USER}" \
  -d "password=${ADMIN_PASS}" | jq -r '.access_token // empty')

if [ -z "$TOKEN" ]; then
  echo "Failed to get token. Check Keycloak admin credentials."
  exit 1
fi

echo "Getting certa client id in realm ${REALM}..."
CLIENT_ID=$(curl -sf -H "Authorization: Bearer ${TOKEN}" "${BASE}/admin/realms/${REALM}/clients?clientId=certa" | jq -r 'if length > 0 then .[0].id else empty end')

if [ -z "$CLIENT_ID" ]; then
  echo "Client certa not found in realm ${REALM}. Ensure realm import completed."
  exit 1
fi

echo "Ensuring certa client has 'admin' role..."
curl -sf -o /dev/null -X POST "${BASE}/admin/realms/${REALM}/clients/${CLIENT_ID}/roles" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"name":"admin"}' 2>/dev/null || true

echo "Getting admin role id..."
ADMIN_ROLE=$(curl -sf -H "Authorization: Bearer ${TOKEN}" "${BASE}/admin/realms/${REALM}/clients/${CLIENT_ID}/roles" | jq -c '[.[] | select(.name=="admin") | {id, name, clientRole: true, containerId}] | .[0]')

if [ -z "$ADMIN_ROLE" ] || [ "$ADMIN_ROLE" = "null" ]; then
  echo "Could not get admin role."
  exit 1
fi

echo "Getting user id for ${TARGET_USER}..."
USER_ID=$(curl -sf -H "Authorization: Bearer ${TOKEN}" "${BASE}/admin/realms/${REALM}/users?username=${TARGET_USER}" | jq -r '.[0].id // empty')

if [ -z "$USER_ID" ]; then
  echo "User ${TARGET_USER} not found in realm ${REALM}."
  exit 1
fi

echo "Assigning certa admin role to user ${TARGET_USER}..."
HTTP=$(curl -sf -w "%{http_code}" -o /dev/null -X POST "${BASE}/admin/realms/${REALM}/users/${USER_ID}/role-mappings/clients/${CLIENT_ID}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "[${ADMIN_ROLE}]")

if [ "$HTTP" = "204" ] || [ "$HTTP" = "200" ]; then
  echo "Keycloak certa setup complete. User ${TARGET_USER} has certa admin role."
  exit 0
fi

echo "Unexpected response: HTTP ${HTTP}"
exit 1
