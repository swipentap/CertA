# E2E test failures – investigation report

## Environment

Tests run against CertA with **embedded OAuth2** (OpenIddict). App at `https://localhost:8443`. Tests use Playwright, BASE_URL, and OAUTH2_TEST_USER/PASSWORD env vars.

---

## 1. OAuth2_login_then_logout_returns_to_app_and_shows_login_link

**Observed:** Timeout 15000ms waiting for `.nav-item.dropdown .nav-link` (user menu).

**Flow (embedded OAuth2):**
1. Test goes to BaseUrl → redirect to /connect/authorize → not authenticated → redirect to /login?returnUrl=...
2. Test fills Email/Password, clicks Login.
3. LoginView submit() does `fetch` POST to /Account/Login. Server signs in, redirects to returnUrl = /connect/authorize?...
4. ConnectController: user authenticated, has Admin → SignIn (OAuth auth code) → redirect to /signin-oidc?code=...
5. OIDC middleware exchanges code, sets cookie, redirects to / (Challenge’s RedirectUri).
6. SPA loads at /. Router beforeEach runs fetchUser() → /api/me. If cookie present, auth.user set, AppLayout renders.
7. AppLayout shows user menu: `.nav-item.dropdown` with inner `.nav-link` (avatar/name).

**Root cause analysis:**

- The test waits for `u.Contains(host) && !u.Contains("signin-oidc")`. As soon as the URL is `/`, the condition passes and the test continues.
- The timeout occurs on `.nav-item.dropdown .nav-link`, so either:
  - The menu element never appears, or
  - It appears too late (after 15s).

**Most likely cause:** Race between URL navigation and SPA render.

1. After OIDC callback, the browser ends up on `/` with the auth cookie.
2. The SPA loads `index.html`, Vue boots, router runs `beforeEach` and `fetchUser()`.
3. `fetchUser()` is async. If `/api/me` is slow or cookie handling is delayed, `auth.isAuthenticated` can still be false when the route is evaluated.
4. Router then does `window.location.href = '/Account/Login?returnUrl=/'` (requiresAuth + oauth2Enabled).
5. That starts a new Challenge → /connect/authorize → /login, and the user never reaches the authenticated home with AppLayout, so the user menu never appears.

Alternatively, Vue/AppLayout might not have finished rendering before the test checks, so the selector finds nothing.

**Conclusion:** The test proceeds as soon as the URL is `/`, but the SPA may not have:
- Finished auth (`fetchUser`),
- Or rendered the navbar.

The test assumes that “URL is /” means “user menu is visible,” which does not always hold with async auth and rendering.

---

## 2. OAuth2_login_without_certa_admin_redirects_to_AccessDenied

**Observed:** Assertion `url.Contains("access-denied")` fails. Actual URL: `https://localhost:8443/`.

**Flow (embedded OAuth2):**
1. Test uses certa_noadmin@certa.local / noadmin123 (or env overrides).
2. Program.cs creates that user without Admin; no `EnsureUserInRoleAsync` call.
3. Test hits BaseUrl → /connect/authorize → /login.
4. Test fills credentials and submits.
5. POST /Account/Login succeeds, sets cookie for certa_noadmin, redirects to returnUrl.
6. returnUrl = /connect/authorize?client_id=...&redirect_uri=...&response_type=code&scope=...
7. ConnectController runs again. User authenticated, `GetUserRolesAsync` returns empty → `hasAdmin` false → `Redirect("/access-denied?message=...")`.

**Root cause analysis:**

Getting `/` instead of `/access-denied` implies either:

1. **ConnectController did not run the no-admin branch** – We never reached the `if (!hasAdmin)` path.
2. **User was treated as admin** – The user used had Admin in DB.
3. **Different flow** – e.g. error path or redirect_uri handling ends at `/`.

**returnUrl parsing (possible cause):**

- ConnectController redirects to `/login?returnUrl={Uri.EscapeDataString(returnUrl)}`, so the value is correctly encoded.
- Vue Router uses `route.query.returnUrl`.
- If the incoming URL is malformed or double-encoded, `returnUrl` could be truncated or wrong.
- Truncated returnUrl (e.g. missing `redirect_uri`) produces an invalid OAuth request. OpenIddict may handle it with an error redirect, possibly to `/` or `/signin-oidc`, which could end up at `/`.

**DB/role check:**

- Program.cs creates certa_noadmin without Admin and does not call `EnsureUserInRoleAsync` for them.
- If certa_noadmin were given Admin elsewhere (script, manual change, migration), the test would see `/` instead of `/access-denied`.

**Conclusion:** Either:
- (A) certa_noadmin has Admin in the DB, or
- (B) returnUrl/OAuth request handling leads to an error redirect to `/` instead of `/access-denied`.

Both would explain the assertion failure.

---

## Summary

| Test | Observed | Likely root cause |
|------|----------|-------------------|
| **OAuth2_login_then_logout** | Timeout on user menu | URL reaches `/` before SPA is ready (fetchUser/AppLayout). Router may redirect unauthenticated users back to /Account/Login, so the menu never appears. Timing/race condition. |
| **OAuth2_login_without_certa_admin** | URL is `/` instead of `access-denied` | Either certa_noadmin has Admin in DB, or invalid OAuth request (e.g. truncated returnUrl) leads to a redirect to `/`. |

---

## Recommendations

1. **OAuth2_login_then_logout:**  
   - Add an explicit wait for the user menu (or a stable SPA element) after the URL check.  
   - Or wait for `/api/me` / network idle before asserting on the navbar.  
   - Ensure the test waits for the SPA to be in an authenticated state, not only for the URL.

2. **OAuth2_login_without_certa_admin:**  
   - Confirm certa_noadmin has no Admin role in the DB.  
   - Inspect returnUrl and OAuth request validation when ConnectController redirects to /login.  
   - Add logging around ConnectController and OpenIddict to trace no-admin redirects and error redirects.
