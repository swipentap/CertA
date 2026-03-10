# Investigation: why no-admin lands on / instead of /access-denied

## Flow that should happen

1. User (no-admin) goes to app → hits `/connect/authorize` → not authenticated → ConnectController redirects to `/login?returnUrl=<encoded full authorize URL>`.
2. User sees login form. SPA: `returnUrl = route.query.returnUrl || '/'`. Form POST sends `ReturnUrl` in body.
3. AccountController Login POST: `redirectUrl = model.ReturnUrl ?? returnUrl`; `RedirectToLocal(redirectUrl)` → 302 to that URL.
4. Browser follows 302 to `/connect/authorize?...` → ConnectController runs, user is authenticated, hasAdmin is false → redirect to `/access-denied`.

## What is verified in code

- **AccountController** (current code): uses `model.ReturnUrl` when non-empty, else query `returnUrl`. So form body ReturnUrl is used for SPA POST.
- **LoginView.vue**: `formData.append('ReturnUrl', returnUrl.value)` and `returnUrl = computed(() => route.query.returnUrl || '/')`. So the form sends whatever the SPA got from the query.
- **ConnectController**: redirects to `/login?returnUrl={Uri.EscapeDataString(returnUrl)}`. So the authorize URL is encoded; `&` becomes `%26` in the query param value.
- **Vue Router / query parsing**: If the browser loads `/login?returnUrl=%2Fconnect%2Fauthorize%3Fclient_id%3Dcerta%26redirect_uri%3D...`, the query string has one parameter `returnUrl` with value (after one decode) `/connect/authorize?client_id=certa&redirect_uri=...`. So the full URL should be in `route.query.returnUrl` unless the environment parses the query in a way that splits on `&` before decoding (then we’d get truncation).

## Why the test might still see /

1. **App under test is an old build** – The process serving the app (e.g. Docker) was not rebuilt/restarted after the AccountController change. So it still redirects using only query `returnUrl` (null) → `/`.
2. **Form ReturnUrl is null or truncated** – If `route.query.returnUrl` is truncated (e.g. parsed as `/connect/authorize?client_id=certa`), then `model.ReturnUrl` is that value. We’d redirect to `/connect/authorize?client_id=certa` (incomplete). OpenIddict might then reject or redirect; behaviour would need to be checked.
3. **Model binding not binding ReturnUrl** – Form key is `ReturnUrl`; property is `LoginViewModel.ReturnUrl`. Standard ASP.NET Core binding is case-insensitive for form keys, so it should bind. If the request is not `application/x-www-form-urlencoded` or `multipart/form-data`, or the key differs, binding could fail.

## How to get the actual reason

- **Logging added**: AccountController Login POST now logs `FormReturnUrl`, `QueryReturnUrl`, and the final `Using` redirect URL.
- **Steps**: Rebuild and restart the app, run the no-admin test, then check app logs for that line. You will see:
  - If `FormReturnUrl` is (null) → form did not send ReturnUrl or it was not bound.
  - If `FormReturnUrl` is truncated (e.g. no `redirect_uri`) → SPA or query parsing truncated it.
  - If `FormReturnUrl` is full but `Using` is `/` → RedirectToLocal is overriding or the log is from different code (old build).

No speculation in this doc; the log output is the evidence.
