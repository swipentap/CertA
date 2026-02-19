# CertA UI tests

Playwright tests run against a **running** CertA instance. Start the app first, then run the tests.

## Prerequisites

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

- **Smoke tests**: Home and Login page return 2xx/3xx and show app or auth content (pass with Keycloak on or off).
- **GET /Account/Logout**: Asserts GET returns 405 (no category; always runs).
- **RequiresKeycloak** (run when Keycloak is on):
  - OAuth2 login (user with certa **admin**) → app → Logout → assert logged out. Set `KEYCLOAK_TEST_USER`, `KEYCLOAK_TEST_PASSWORD`.
  - OAuth2 login (user **without** certa admin) → AccessDenied. Set `KEYCLOAK_TEST_USER_NO_ADMIN`, `KEYCLOAK_TEST_PASSWORD_NO_ADMIN` (skipped if unset).
- **RequiresLocalAuth** (run when Keycloak is off; skipped if app redirects to Keycloak):
  - Local login → Logout → home and Login link.
  - Local invalid credentials → stay on Login with error.
- Run only Keycloak tests: `--filter "Category=RequiresKeycloak"`.
- Run only local auth tests: `--filter "Category=RequiresLocalAuth"`.
- Run only smoke + GET 405: `--filter "Category!=RequiresLocalAuth&Category!=RequiresKeycloak"`.

## Run all tests

Two app instances are needed (Keycloak on + Keycloak off):

1. **Keycloak tests** (Docker certa-app at https://localhost:8443):
   ```bash
   # Create no-admin user first (one-time):
   ./scripts/create-keycloak-user-noadmin.sh

   KEYCLOAK_TEST_USER=admin KEYCLOAK_TEST_PASSWORD=admin \
   KEYCLOAK_TEST_USER_NO_ADMIN=certa_noadmin KEYCLOAK_TEST_PASSWORD_NO_ADMIN=noadmin123 \
   BASE_URL=https://localhost:8443 PLAYWRIGHT_BROWSERS_PATH="$(pwd)/CertA.UITests/bin/Debug/net9.0/.playwright" \
   dotnet test CertA.UITests --filter "Category!=RequiresLocalAuth"
   ```

2. **Local auth tests** (CertA with Keycloak disabled on another port):
   ```bash
   # Terminal 1: run CertA with Keycloak off
   Authentication__Keycloak__Enabled=false ConnectionStrings__DefaultConnection="Host=localhost;Port=5433;Database=certa;Username=certa;Password=certa123" \
   dotnet run --project CertA

   # Terminal 2: run local auth tests (adjust BASE_URL if app uses different port)
   BASE_URL=http://localhost:5181 PLAYWRIGHT_BROWSERS_PATH="$(pwd)/CertA.UITests/bin/Debug/net9.0/.playwright" \
   dotnet test CertA.UITests --filter "Category=RequiresLocalAuth"
   ```
