#!/usr/bin/env bash
# Create a Keycloak user WITHOUT certa admin role (for UI test OAuth2_login_without_certa_admin).
# Usage: KEYCLOAK_ADMIN_USER=admin KEYCLOAK_ADMIN_PASSWORD=admin ./create-keycloak-user-noadmin.sh

set -e

BASE="${KEYCLOAK_BASE_URL:-https://auth.dev.net/auth}"
REALM="${KEYCLOAK_REALM:-master}"
ADMIN_USER="${KEYCLOAK_ADMIN_USER:-admin}"
ADMIN_PASS="${KEYCLOAK_ADMIN_PASSWORD:-admin}"
USERNAME="${KEYCLOAK_NOADMIN_USER:-certa_noadmin}"
PASSWORD="${KEYCLOAK_NOADMIN_PASSWORD:-noadmin123}"

echo "Getting admin token..."
TOKEN=$(curl -sk -X POST "${BASE}/realms/${REALM}/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" -d "client_id=admin-cli" \
  -d "username=${ADMIN_USER}" -d "password=${ADMIN_PASS}" | jq -r '.access_token')
if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
  echo "Failed to get token."
  exit 1
fi

echo "Creating user ${USERNAME} (no certa admin role)..."
HTTP=$(curl -sk -w "%{http_code}" -o /tmp/create-user-resp.json -X POST "${BASE}/admin/realms/${REALM}/users" \
  -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" \
  -d "{\"enabled\":true,\"username\":\"${USERNAME}\",\"email\":\"${USERNAME}@test.local\",\"firstName\":\"No\",\"lastName\":\"Admin\",\"credentials\":[{\"type\":\"password\",\"value\":\"${PASSWORD}\",\"temporary\":false}]}")

if [ "$HTTP" = "201" ]; then
  echo "User ${USERNAME} created. Use KEYCLOAK_TEST_USER_NO_ADMIN=${USERNAME} KEYCLOAK_TEST_PASSWORD_NO_ADMIN=${PASSWORD} for the no-admin test."
  exit 0
fi

if [ "$HTTP" = "409" ]; then
  echo "User ${USERNAME} already exists. Resetting password and ensuring no certa admin role..."
  USER_ID=$(curl -sk -H "Authorization: Bearer ${TOKEN}" "${BASE}/admin/realms/${REALM}/users?username=${USERNAME}" | jq -r '.[0].id')
  if [ -z "$USER_ID" ] || [ "$USER_ID" = "null" ]; then
    echo "Could not get user id."
    exit 1
  fi
  curl -sk -X PUT "${BASE}/admin/realms/${REALM}/users/${USER_ID}/reset-password" \
    -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" \
    -d "{\"type\":\"password\",\"value\":\"${PASSWORD}\",\"temporary\":false}"
  CLIENT_ID=$(curl -sk -H "Authorization: Bearer ${TOKEN}" "${BASE}/admin/realms/${REALM}/clients?clientId=certa" | jq -r '.[0].id')
  if [ -n "$CLIENT_ID" ] && [ "$CLIENT_ID" != "null" ]; then
    ROLES=$(curl -sk -H "Authorization: Bearer ${TOKEN}" "${BASE}/admin/realms/${REALM}/users/${USER_ID}/role-mappings/clients/${CLIENT_ID}")
    ADMIN_ROLE=$(echo "$ROLES" | jq -r '.[] | select(.name=="admin") | {id, name, clientRole: true, containerId}')
    if [ -n "$ADMIN_ROLE" ] && [ "$ADMIN_ROLE" != "null" ]; then
      curl -sk -X DELETE "${BASE}/admin/realms/${REALM}/users/${USER_ID}/role-mappings/clients/${CLIENT_ID}" \
        -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" -d "[${ADMIN_ROLE}]"
      echo "Removed certa admin role from user ${USERNAME}."
    fi
  fi
  echo "Done. User ${USERNAME} has no certa admin role."
  exit 0
fi

echo "Unexpected response: HTTP $HTTP"
cat /tmp/create-user-resp.json
exit 1
