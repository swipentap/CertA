# SPA_local_login_then_logout – why we stay on login page

## What the test does

1. Go to `/login`.
2. Fill email/password, click Login (form is submitted via `fetch('/Account/Login', { method: 'POST', body: formData })`).
3. Expect URL to change away from login (we should be on app or redirect target).

## When we stay on login

The SPA leaves the login page only when:

- `res.redirected === true`: then it sets `window.location.href = res.url` (full navigation), or
- `res.ok` and no redirect: then it does `router.push(returnUrl.value)`.

So if the URL still contains "login" after submit, the SPA did not perform one of those navigations. So either:

- The server did not return a redirect (302). So the response was 200 or 4xx. Then `res.redirected` is false; if also `res.ok` is false, we don’t call `router.push`, and we stay on the same page.
- Or the server did return a redirect to a URL that still contains "login" (e.g. `/login?error=...`). Then we would navigate to that URL and the test would still see "login" in the URL.

## Established cause (no speculation)

**The test remains on the login page because the POST /Account/Login response did not cause the client to navigate away.** That means either:

1. The response was **not a redirect** (no 302). So it was 200 or 4xx (e.g. 400 Bad Request from `[ValidateAntiForgeryToken]`). Then `res.redirected` is false; if `res.ok` is false, the SPA never calls `router.push` and stays on login.
2. Or the response **was a redirect** to a URL that still contains "login" (e.g. 302 to `/login?error=...`). Then the client navigates but remains on a login URL.

To know which it is: inspect the response in the test (status code and Location header) or add server-side logging for the Login POST (e.g. whether it returns Redirect vs returning a view or error). The log will show the actual behaviour.
