# E2E failures – why

## 1. OAuth2_login_without_certa_admin → lands on / or chrome-error

**Why (returnUrl):** Query string parsing splits on `&`. The `returnUrl` value contains `&` (e.g. `...&redirect_uri=...`). So the parser treats the first `&` as the start of the next parameter and the value is cut there.

**Why (onExternalIdP false positive):** `currentUrl.Contains("auth")` matches `/connect/authorize`, so the test wrongly treated embedded flow as external IdP (Keycloak) and tried to fill Keycloak form fields that don't exist. **Fix:** Only treat as external IdP when URL contains `keycloak` or `openid-connect/auth`.

**Why (chrome-error):** With embedded OAuth2, when on app login we use request API and assert on API response (loginRes.Url, body). When on external IdP we use form submit; Chromium can land on `chrome-error://chromewebdata/` after form-driven redirects. **Fix:** For embedded (onAppLogin), verify via API response and return early; avoid page navigation to access-denied.

## 2. OAuth2_login_then_logout → timeout on Logout

**Why:** The session cookie is not sent (or not set yet) when the SPA calls `/api/me` right after load. Playwright may not store cookies from 302 responses in form-driven navigations. **Fix:** Use request API for login (antiforgery GET, Login POST) so cookies are correctly stored and shared with the page; then `page.GotoAsync("/")`.

## 3. After_login_logout and SPA_local_login_then_logout → still on login

**Why:** The antiforgery cookie and the form token do not match when the POST is made (e.g. cookie not sent with the request, or token and cookie from different requests/contexts), so validation fails and the server returns 4xx instead of 302. **Fix:** Use request API for login instead of form submit.
