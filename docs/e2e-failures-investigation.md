# E2E test failures – investigation (evidence-based)

## Flow traced in code

### What happens when the test goes to BaseUrl (https://localhost:8443)

1. **GET /** → `MapControllerRoute` matches `Home/Index`.  
   `HomeController.Index()`: user not authenticated → `RedirectToAction("Login", "Account")` → **302 to /Account/Login**.

2. **GET /Account/Login** → `AccountController.Login(GET)`: OAuth2 enabled → `Challenge(OpenIdConnect)` → **302 to IdP** (e.g. `https://auth.dev.net/auth/realms/master/protocol/openid-connect/auth?client_id=certa&redirect_uri=https://localhost:8443/signin-oidc&...`).

3. Test fills IdP username/password and submits. IdP redirects to **https://localhost:8443/signin-oidc?code=...&state=...**.

4. **GET /signin-oidc** → OIDC middleware: exchanges code, runs `OnTokenValidated`. If user has certa admin role → build principal, complete → **302 to RedirectUri** which is **"/"** (from Challenge).

5. **GET /** (with cookie) → `HomeController.Index()`: user **is** authenticated → **returns View(dashboardData)** → **Razor view with _Layout.cshtml**, **not** the Vue SPA.

So after a successful OAuth2 login the browser ends up on the **Razor dashboard** (`Home/Index` + `_Layout.cshtml`), not on the Vue app.

---

## 1. OAuth2_login_then_logout – timeout waiting for Logout button

**Observed:** Timeout waiting for `GetByRole(AriaRole.Button, Name = "Logout")` to be visible.

**Evidence from code:**

- **Razor _Layout.cshtml (lines 51–67):** When `isLoggedIn` is true, the user menu is a **Bootstrap 5 dropdown**:
  - Toggle: `<a class="nav-link dropdown-toggle" ... data-bs-toggle="dropdown" aria-expanded="false">`.
  - Menu: `<ul class="dropdown-menu">` containing Profile link and a **form with `<button type="submit" class="dropdown-item">... Logout</button>`**.
- The **Logout** button is **inside the dropdown menu**. The menu is **closed by default** (`aria-expanded="false"`). It opens only when the toggle is clicked and Bootstrap JS runs (`data-bs-toggle="dropdown"`).
- Test does: `userMenu = page.Locator("a.dropdown-toggle, .nav-item.dropdown .nav-link").First` → click → `WaitForTimeoutAsync(300)` → `GetByRole(AriaRole.Button, Name = "Logout").WaitForAsync(..., Timeout = 15000)`.

**Conclusion:** The test assumes that after clicking the user menu, the **Bootstrap dropdown opens** and the Logout button becomes visible. If the dropdown **does not open** (e.g. Bootstrap JS not yet run, or click not triggering it in headless), the Logout button stays inside the closed menu and is **not visible** to Playwright, so the test times out.

**Root cause (evidence-based):** Logout is inside a Bootstrap dropdown that must open on click. The dropdown is not opening in the test environment (timing and/or headless behavior), so the Logout button is never visible.

---

## 2. OAuth2_login_without_certa_admin – expected AccessDenied, got /

**Observed:** Assertion `url.Contains("AccessDenied")` fails; actual URL is `https://localhost:8443/`.

**Evidence from code:**

- **Program.cs OnTokenValidated (lines 208–218):** CertA reads roles from the access token (`resource_access.<clientId>.roles`). If there is no role `"admin"` (case-insensitive), it calls `context.Fail("Access requires the certa admin role.")`.
- **OnRemoteFailure (lines 139–145):** On failure, redirect to `/Account/AccessDenied?message=...`.
- So if the **certa_noadmin** user has **no** certa client role **admin** on the IdP, the callback should fail and we should land on **AccessDenied**. If we land on **/** instead, then either:
  - The user **has** the certa admin role on the IdP (so CertA accepts and redirects to "/"), or
  - The user does not exist or login at the IdP failed, and the test never reached the CertA callback (e.g. stayed on IdP or got an error page), and the reported URL might be from a different navigation or retry.

**Conclusion:** The test expects AccessDenied. Getting `/` means the app treated the user as successfully authenticated and sent them to Home. So either the no-admin user actually has the admin role on the IdP, or the flow under test did not hit the CertA callback with that user (e.g. wrong user used, or IdP error before callback).

**Root cause (evidence-based):** Either the IdP user used in the test has the certa **admin** role (so CertA correctly redirects to "/"), or the test did not complete an IdP login as the no-admin user before the assertion (e.g. wrong user or failed login). Needs verification of IdP role assignment and which user the test actually logs in as.

---

## 3. After_login_logout_returns_to_home_and_shows_login_link

**Observed:** `Assert.That(onLogin || hasLoginLink || onIdP, Is.True)` fails.

**Evidence from code:**

- This test is **RequiresLocalAuth**: it expects **OAuth2 disabled** and uses local credentials (admin@certa.local). If the app has OAuth2 enabled, the test fails earlier with `Assert.Fail("OAuth2 is enabled; run local-auth tests with OAuth2 disabled.")` when it sees an IdP redirect on GET /login.
- So when this assertion runs, the test **believes** it’s in local-auth mode (it didn’t see an IdP redirect). Flow: GET /login → local form → POST credentials → redirect (e.g. to "/") → click Logout → POST /Account/Logout → server redirects to **"/"** (Home).
- After that redirect the browser is on **GET /** with no cookie. **GET /** → `HomeController.Index()`: not authenticated → **RedirectToAction("Login", "Account")** → 302 to **/Account/Login**. So the **final** URL should be **/Account/Login** (or the Vue `/login` if the SPA handles it). The test then reads `page.Url` and checks `hasLoginLink` (GetByRole Link "Login") and `hasLoginButton`.
- **Vue LoginView:** The submit control is a **button** with text "Login", not a link. So `GetByRole(AriaRole.Link, Name = "Login")` may not find anything on the login page. The test was updated to also check `hasLoginButton`.
- **Razor login page:** Has `<a class="nav-link" href="/Account/Login">... Login</a>` in the nav when not logged in. So if we land on a Razor page (e.g. Login view), there can be a Login **link** in the nav.
- If the test runs against the **Vue SPA** (e.g. fallback to index.html for some path), after logout we might land on **/** and the Vue router might redirect to **/login** asynchronously. The test may be reading URL and visibility **before** that client-side navigation completes, so `onLogin` is false and no Login link/button is visible yet.

**Conclusion:** The failure can be due to (1) asserting before the post-logout redirect to the login page completes (timing), and/or (2) the login page only exposing a "Login" **button**, so a check for a "Login" **link** alone can fail. The test was later updated to wait for URL containing "login" and to accept a Login button; if the failure persists, the next step is to confirm the exact page and DOM at assertion time (Razor vs Vue, and which elements are visible).

**Root cause (evidence-based):** Either the assertion runs before the redirect to the login page has finished (timing), or the visible “Login” control is a button rather than a link and the test’s conditions did not account for that. Requires checking the exact URL and DOM at the moment of the assertion.

---

## 4. SPA_local_login_then_logout

**Observed:** "After login still on login page (OAuth2 may be enabled or auth failed)."

**Evidence from code:**

- Test goes to **BASE_URL/login**. If the app is the **Vue SPA**, that is the client route `/login` (LoginView). If the app serves **Razor** for some paths, GET /login might not exist and fallback could serve the SPA.
- **Router (router/index.js):** For routes with `meta: { requiresAuth: true }`, if `!auth.isAuthenticated`, then if `auth.oauth2Enabled` → `window.location.href = '/Account/Login?returnUrl=...'` (full redirect to server). So if OAuth2 is enabled, unauthenticated access to "/" triggers a redirect to **/Account/Login**, which then Challenges to the IdP. So the test never sees the **local** login form when OAuth2 is on.
- Test fills Email/Password and clicks Login. If OAuth2 is enabled, the server’s POST /Account/Login is still used; with OAuth2 enabled, the **GET** /Account/Login does Challenge, but the **POST** /Account/Login still runs the local SignInAsync. So local login can succeed if the user hits the local form. But if the test initially landed on **/Account/Login** and was redirected to the IdP, it never gets to the local form. So "still on login page" can mean: we're on the Vue `/login` or /Account/Login and the **next** navigation (after submit) didn’t change the URL (e.g. still on `/login`), which happens when OAuth2 is enabled and the test expected a successful local login (redirect to home).

**Conclusion:** When OAuth2 is enabled, the app redirects unauthenticated users to the IdP. The test is written for **local auth only**. So with the current (OAuth2-on) config, this test is expected to fail: it assumes local login is available and that after submit we leave the login page; with OAuth2 on, either we never see the local form or the submit doesn’t result in the expected navigation.

**Root cause (evidence-based):** Test is for local-auth only. The app under test has OAuth2 enabled, so local login is not the active path; the test’s preconditions (local form and post-login redirect) are not met.

---

## Summary (evidence-based)

| Test | What the code does | Why it can fail |
|------|--------------------|------------------|
| **OAuth2_login_then_logout** | After callback, user is on **Razor** Home/Index with _Layout. Logout is inside a **Bootstrap dropdown**. Test clicks toggle then waits for Logout button. | Dropdown does not open in the test (Bootstrap JS / click behavior), so Logout stays hidden and the test times out. |
| **OAuth2_login_without_certa_admin** | CertA fails OnTokenValidated when user has no certa admin role and redirects to AccessDenied. | Test gets "/" → either the IdP user has admin role, or the test didn’t complete login as the no-admin user. Need to confirm IdP roles and which user is used. |
| **After_login_logout_returns_to_home** | Logout redirects to "/"; then server redirects to /Account/Login. Test checks URL and Login link/button. | Assertion runs before redirect completes and/or only checks for Login **link** while the page has a Login **button**. |
| **SPA_local_login_then_logout** | Requires local auth; expects to leave login page after submit. | App has OAuth2 enabled, so local login is not the primary path; test preconditions are not met. |

No code was changed in this investigation.
