# CertA UI tests

Playwright tests run against a **running** CertA instance. Start the app first, then run the tests.

## Run tests with app (build + start + test in one go)

From repo root, rebuild the app, start it, wait for health, then run all UI tests:

```bash
./scripts/run-e2e-with-app.sh
```

Add `--down` to tear down containers after the test run. Add dotnet test filter args after:

```bash
./scripts/run-e2e-with-app.sh --down
./scripts/run-e2e-with-app.sh --filter "Category=RequiresOAuth2"
```

This uses `docker compose -f docker-compose.yml -f docker-compose.embedded.yml up --build -d`, so the tests always run against the current code.

## Prerequisites (when running tests manually)

1. **CertA running** (e.g. `docker compose up -d` or `dotnet run --project CertA`).
2. **Playwright Chromium** (one-time). From repo root:
   ```bash
   cd CertA.UITests/bin/Debug/net9.0
   PLAYWRIGHT_BROWSERS_PATH=$PWD/.playwright npx playwright@1.49 install chromium
   cd ../../..
   ```

## Run tests

```bash
# From repo root. Default BASE_URL is https://localhost:8443.
PLAYWRIGHT_BROWSERS_PATH="$(pwd)/CertA.UITests/bin/Debug/net9.0/.playwright" dotnet test CertA.UITests

# Override app URL if needed:
BASE_URL=http://localhost:5000 PLAYWRIGHT_BROWSERS_PATH="$(pwd)/CertA.UITests/bin/Debug/net9.0/.playwright" dotnet test CertA.UITests
```

- **Smoke tests**: Home and Login page return 2xx/3xx and show app or auth content (pass with OAuth2 on or off).
- **GET /Account/Logout**: Asserts GET returns 405 (no category; always runs).
- **RequiresOAuth2** (run when OAuth2 is on):
  - OAuth2 login (user with certa **admin**) → app → Logout → assert logged out. Set `OAUTH2_TEST_USER`, `OAUTH2_TEST_PASSWORD`.
  - OAuth2 login (user **without** certa admin) → AccessDenied. Set `OAUTH2_TEST_USER_NO_ADMIN`, `OAUTH2_TEST_PASSWORD_NO_ADMIN` (skipped if unset).
- **RequiresLocalAuth** (run when OAuth2 is off; skipped if app redirects to IdP):
  - Local login → Logout → home and Login link.
  - Local invalid credentials → stay on Login with error.
- Run only OAuth2 tests: `--filter "Category=RequiresOAuth2"`.
- Run only local auth tests: `--filter "Category=RequiresLocalAuth"`.
- Run only smoke + GET 405: `--filter "Category!=RequiresLocalAuth&Category!=RequiresOAuth2"`.

## Run all tests

Two app instances are needed (OAuth2 on + OAuth2 off):

1. **OAuth2 tests** (Docker certa-app at https://localhost:8443):
   ```bash
   # Create no-admin user first (one-time):
   ./scripts/create-oauth2-user-noadmin.sh

   OAUTH2_TEST_USER=admin OAUTH2_TEST_PASSWORD=admin \
   OAUTH2_TEST_USER_NO_ADMIN=certa_noadmin OAUTH2_TEST_PASSWORD_NO_ADMIN=noadmin123 \
   BASE_URL=https://localhost:8443 PLAYWRIGHT_BROWSERS_PATH="$(pwd)/CertA.UITests/bin/Debug/net9.0/.playwright" \
   dotnet test CertA.UITests --filter "Category!=RequiresLocalAuth"
   ```

2. **Local auth tests** (CertA with OAuth2 disabled). Option A – Docker:
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.local-auth.yml up -d
   BASE_URL=https://localhost:8444 PLAYWRIGHT_BROWSERS_PATH="$(pwd)/CertA.UITests/bin/Debug/net9.0/.playwright" \
   dotnet test CertA.UITests --filter "Category=RequiresLocalAuth"
   ```
   Option B – dotnet run:
   ```bash
   # Terminal 1: run CertA with OAuth2 off
   Authentication__OAuth2__Enabled=false ConnectionStrings__DefaultConnection="Host=localhost;Port=5433;Database=certa;Username=certa;Password=certa123" \
   dotnet run --project CertA

   # Terminal 2: run local auth tests (adjust BASE_URL if app uses different port)
   BASE_URL=http://localhost:5181 PLAYWRIGHT_BROWSERS_PATH="$(pwd)/CertA.UITests/bin/Debug/net9.0/.playwright" \
   dotnet test CertA.UITests --filter "Category=RequiresLocalAuth"
   ```
