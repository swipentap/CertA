#!/usr/bin/env bash
# Build and start CertA (embedded OAuth2), wait for readiness, run UI tests, then optionally tear down.
# Usage: from repo root:
#   ./scripts/run-e2e-with-app.sh              # up --build, test, leave containers up
#   ./scripts/run-e2e-with-app.sh --down       # up --build, test, then compose down
#   ./scripts/run-e2e-with-app.sh --filter "Category=RequiresOAuth2"  # run only OAuth2 tests
set -e
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

TEARDOWN=
TEST_ARGS=()
for a in "$@"; do
  if [ "$a" = "--down" ]; then TEARDOWN=1; else TEST_ARGS+=("$a"); fi
done

COMPOSE="docker compose -f docker-compose.yml -f docker-compose.embedded.yml"
BASE_URL="${BASE_URL:-https://localhost:8443}"
export BASE_URL
export OAUTH2_TEST_USER="${OAUTH2_TEST_USER:-admin@certa.local}"
export OAUTH2_TEST_PASSWORD="${OAUTH2_TEST_PASSWORD:-Admin123!}"
export OAUTH2_TEST_USER_NO_ADMIN="${OAUTH2_TEST_USER_NO_ADMIN:-certa_noadmin@certa.local}"
export OAUTH2_TEST_PASSWORD_NO_ADMIN="${OAUTH2_TEST_PASSWORD_NO_ADMIN:-noadmin123}"
export PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH:-$REPO_ROOT/CertA.UITests/bin/Release/net9.0/.playwright}"

echo "Building and starting app..."
$COMPOSE up --build -d

echo "Waiting for app to be healthy..."
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  if curl -sk -o /dev/null -w "%{http_code}" "$BASE_URL/health" 2>/dev/null | grep -q 200; then
    echo "App ready."
    break
  fi
  if [ "$i" -eq 15 ]; then
    echo "App did not become healthy in time."
    $COMPOSE logs certa-app --tail=50
    exit 1
  fi
  sleep 3
done

echo "Running UI tests..."
dotnet test "$REPO_ROOT/CertA.UITests/CertA.UITests.csproj" -c Release --logger "console;verbosity=normal" -- "${TEST_ARGS[@]}"

EXIT=$?
if [ -n "$TEARDOWN" ]; then
  echo "Tearing down..."
  $COMPOSE down
fi
exit $EXIT
