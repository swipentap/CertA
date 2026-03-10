# OAuth2 E2E failures – investigation (root causes)

## 1. OAuth2_login_then_logout – timeout on user menu (not “timeout” as root cause)

**Observed:** Test times out waiting for `.nav-item.dropdown .nav-link` (user menu) to be visible.

**Root cause:** The user menu exists only in `AppLayout.vue`, which is used for routes under `/` (Home, Certificates, etc.). The `/login` route uses `LoginView.vue` alone – no AppLayout, so no user dropdown in the DOM.

After embedded OAuth2 login the test does `WaitForURLAsync(host && !signin-oidc)` then immediately waits for the user menu. So we can end up on either:

- **`/`** – AppLayout is shown, dropdown is present (once auth is ready).
- **`/login`** – Only LoginView is shown; there is no `.nav-item.dropdown`, so the locator never appears and the test times out.

Why would we land on `/login`? Router `beforeEach` runs on navigation and calls `auth.fetchUser()` (GET `/api/me`). If that returns non‑OK (e.g. 401) or fails, `auth.user` stays null, so `isAuthenticated` is false. For any route with `meta: { requiresAuth: true }` (including `/`), the guard then redirects to Login. So if the session cookie is not yet visible to `/api/me` when the SPA first loads after the OAuth2 callback (timing/cookie path), the app treats the user as unauthenticated and sends them to `/login`. The test then waits for a selector that only exists on the app layout, so it times out. So the underlying reason for the “timeout” is: **ending up on `/login` (no layout, no dropdown) because the app thinks the user is not authenticated right after the callback.**

---

## 2. OAuth2_login_without_certa_admin – lands on `/` instead of `/access-denied`

**Observed:** After logging in as certa_noadmin, final URL is `https://localhost:8443/`; test expects URL to contain `access-denied`.

**Root cause (code bug):** In `AccountController.cs`, the Login **POST** action uses the `returnUrl` **parameter** (from the query string) when redirecting:

```csharp
return RedirectToLocal(returnUrl);  // line 156
```

The SPA submits the form via `fetch('/Account/Login', { method: 'POST', body: formData })` with **no query string**. The intended return URL is sent in the **body** as `ReturnUrl` (bound to `model.ReturnUrl`). The action never uses `model.ReturnUrl`; it only uses the `returnUrl` parameter, which is null on a POST with no query. So `RedirectToLocal(null)` runs, which does `RedirectToAction("Index", "Home")` → redirect to `/`. So **every** SPA form login (including no-admin) is sent to `/` instead of the form’s `ReturnUrl` (e.g. `/connect/authorize?...`). For no-admin, that means we never hit ConnectController again after login, so we never get the “Admin role required” redirect to `/access-denied`; we just land on `/`.

---

## Summary

| Test | Real cause (not “timeout” / “wrong page”) |
|------|-------------------------------------------|
| 1. login_then_logout | After callback, SPA can redirect to `/login` because `fetchUser()`/`/api/me` doesn’t see the session yet; user menu exists only on AppLayout (not on login page), so the test times out. |
| 2. no-admin access-denied | Login POST uses query `returnUrl` (null for SPA POST) instead of form `model.ReturnUrl`, so redirect is always `/` and ConnectController’s `/access-denied` redirect is never reached. |

---

## Suggestions

### Fix for failure 2 (implemented)

- **AccountController Login POST:** Use the return URL from the form when present, so SPA form login redirects to the intended URL (e.g. `/connect/authorize?...`) and no-admin hits ConnectController and gets redirected to `/access-denied`.
- Change: `return RedirectToLocal(model.ReturnUrl ?? returnUrl);` (or equivalent so form `ReturnUrl` takes precedence over query `returnUrl`).

### Fix for failure 1 (options; pick one or combine)

1. **Test resilience:** After `WaitForURLAsync` (host and not signin-oidc), assert we are not on `/login` (e.g. `Assert.That(page.Url, Does.Not.Contain("/login"), "Landed on login – auth may not be ready after callback.")`). Then wait for a selector that only exists on AppLayout (e.g. a link with text "My Certificates" or the avatar) before waiting for the user dropdown; if we’re still on login, fail with a clear message instead of timing out on the dropdown.
2. **App timing:** Ensure the OIDC callback response sets the session cookie and that the redirect to the SPA happens only after the cookie is set, so the first load of the SPA already has a valid session and `fetchUser()`/`/api/me` succeeds.
3. **Stronger wait:** Before waiting for the user menu, wait for a short period or for a “logged-in” signal (e.g. element that only appears when `auth.user` is set), then wait for the dropdown with a clear failure message if the current URL is `/login` (e.g. “Expected app home but still on login – possible auth timing issue”).
