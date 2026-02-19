#!/usr/bin/env bash
# Create the CertA client in Keycloak via Admin API.
# Usage: KEYCLOAK_BASE_URL=https://auth.dev.net/auth KEYCLOAK_REALM=master KEYCLOAK_ADMIN_USER=admin KEYCLOAK_ADMIN_PASSWORD=admin ./create-keycloak-client.sh
# Or run with defaults: KEYCLOAK_ADMIN_USER=admin KEYCLOAK_ADMIN_PASSWORD=admin ./create-keycloak-client.sh

set -e

BASE="${KEYCLOAK_BASE_URL:-https://auth.dev.net/auth}"
REALM="${KEYCLOAK_REALM:-master}"
ADMIN_USER="${KEYCLOAK_ADMIN_USER:-admin}"
ADMIN_PASS="${KEYCLOAK_ADMIN_PASSWORD:-admin}"
CERTA_URL="${CERTA_BASE_URL:-https://localhost:8443}"

echo "Getting admin token from ${BASE}/realms/${REALM} ..."
TOKEN=$(curl -sk -X POST "${BASE}/realms/${REALM}/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=admin-cli" \
  -d "username=${ADMIN_USER}" \
  -d "password=${ADMIN_PASS}" | jq -r '.access_token')

if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
  echo "Failed to get token. Check BASE URL, realm, and admin credentials."
  exit 1
fi

echo "Creating client 'certa' in realm ${REALM} ..."
HTTP=$(curl -sk -w "%{http_code}" -o ./certa-client-resp.json -X POST "${BASE}/admin/realms/${REALM}/clients" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
    \"clientId\": \"certa\",
    \"enabled\": true,
    \"publicClient\": true,
    \"standardFlowEnabled\": true,
    \"directAccessGrantsEnabled\": false,
    \"rootUrl\": \"${CERTA_URL}\",
    \"redirectUris\": [\"${CERTA_URL}/signin-oidc\", \"${CERTA_URL}/*\"],
    \"webOrigins\": [\"${CERTA_URL}\", \"+\"],
    \"attributes\": { \"post.logout.redirect.uris\": \"+\" }
  }")

if [ "$HTTP" = "201" ]; then
  echo "Client 'certa' created (with post logout redirect URIs)."
  exit 0
fi

if [ "$HTTP" = "409" ]; then
  echo "Client 'certa' already exists. Updating post logout redirect URIs..."
  CLIENT_ID=$(curl -sk -H "Authorization: Bearer ${TOKEN}" "${BASE}/admin/realms/${REALM}/clients?clientId=certa" | jq -r '.[0].id')
  if [ -z "$CLIENT_ID" ] || [ "$CLIENT_ID" = "null" ]; then
    echo "Could not get client id."
    exit 1
  fi
  curl -sk -X GET -H "Authorization: Bearer ${TOKEN}" "${BASE}/admin/realms/${REALM}/clients/${CLIENT_ID}" -o ./certa-client-get.json
  jq '.attributes = ((.attributes // {}) + {"post.logout.redirect.uris": "+"})' ./certa-client-get.json > ./certa-client-patch.json
  HTTP2=$(curl -sk -w "%{http_code}" -o ./certa-client-resp2.json -X PUT "${BASE}/admin/realms/${REALM}/clients/${CLIENT_ID}" \
    -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" -d @./certa-client-patch.json)
  if [ "$HTTP2" = "204" ] || [ "$HTTP2" = "200" ]; then
    echo "Client 'certa' updated with post logout redirect URIs."
    exit 0
  fi
  echo "Update failed: HTTP $HTTP2"
  cat ./certa-client-resp2.json
  exit 1
fi

if [ "$HTTP" = "400" ]; then
  echo "Response ($HTTP): $(cat ./certa-client-resp.json)"
  exit 1
fi

echo "Unexpected response: HTTP $HTTP"
cat ./certa-client-resp.json
exit 1
