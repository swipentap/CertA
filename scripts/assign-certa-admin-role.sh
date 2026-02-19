#!/usr/bin/env bash
# Assign the certa client role "admin" to a Keycloak user (so CertA accepts them).
# Usage: KEYCLOAK_ADMIN_USER=admin KEYCLOAK_ADMIN_PASSWORD=admin KEYCLOAK_TEST_USER=admin ./assign-certa-admin-role.sh

set -e

BASE="${KEYCLOAK_BASE_URL:-https://auth.dev.net/auth}"
REALM="${KEYCLOAK_REALM:-master}"
ADMIN_USER="${KEYCLOAK_ADMIN_USER:-admin}"
ADMIN_PASS="${KEYCLOAK_ADMIN_PASSWORD:-admin}"
TARGET_USER="${KEYCLOAK_TEST_USER:-admin}"

echo "Getting admin token..."
TOKEN=$(curl -sk -X POST "${BASE}/realms/${REALM}/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" -d "client_id=admin-cli" \
  -d "username=${ADMIN_USER}" -d "password=${ADMIN_PASS}" | jq -r '.access_token')
if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
  echo "Failed to get token."
  exit 1
fi

echo "Getting certa client id..."
CLIENT_ID=$(curl -sk -H "Authorization: Bearer ${TOKEN}" "${BASE}/admin/realms/${REALM}/clients?clientId=certa" | jq -r '.[0].id')
if [ -z "$CLIENT_ID" ] || [ "$CLIENT_ID" = "null" ]; then
  echo "Client certa not found. Run create-keycloak-client.sh first."
  exit 1
fi

echo "Ensuring certa client has 'admin' role..."
curl -sk -o /dev/null -w "%{http_code}" -X POST "${BASE}/admin/realms/${REALM}/clients/${CLIENT_ID}/roles" \
  -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" -d '{"name":"admin"}' | grep -q 201 || true
ROLES=$(curl -sk -H "Authorization: Bearer ${TOKEN}" "${BASE}/admin/realms/${REALM}/clients/${CLIENT_ID}/roles")
ADMIN_ROLE_ID=$(echo "$ROLES" | jq -r '.[] | select(.name=="admin") | .id')
if [ -z "$ADMIN_ROLE_ID" ] || [ "$ADMIN_ROLE_ID" = "null" ]; then
  echo "Could not get admin role id."
  exit 1
fi

echo "Getting user id for ${TARGET_USER}..."
USER_ID=$(curl -sk -H "Authorization: Bearer ${TOKEN}" "${BASE}/admin/realms/${REALM}/users?username=${TARGET_USER}" | jq -r '.[0].id')
if [ -z "$USER_ID" ] || [ "$USER_ID" = "null" ]; then
  echo "User ${TARGET_USER} not found."
  exit 1
fi

echo "Assigning certa admin role to user ${TARGET_USER}..."
ROLE_JSON=$(echo "$ROLES" | jq -c '[.[] | select(.name=="admin") | {id, name, clientRole: true, containerId}] | .[0]')
HTTP=$(curl -sk -w "%{http_code}" -o ./role-mapping-resp.json -X POST "${BASE}/admin/realms/${REALM}/users/${USER_ID}/role-mappings/clients/${CLIENT_ID}" \
  -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" -d "[${ROLE_JSON}]")
if [ "$HTTP" = "204" ] || [ "$HTTP" = "200" ]; then
  echo "Role assigned. User ${TARGET_USER} can now sign in to CertA with certa admin role."
  exit 0
fi
echo "Unexpected response: HTTP $HTTP"
cat ./role-mapping-resp.json
exit 1
