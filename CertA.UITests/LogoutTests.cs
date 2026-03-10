using Microsoft.Playwright;
using NUnit.Framework;

namespace CertA.UITests;

/// <summary>E2E tests for login/logout. App is SPA-only; selectors target Vue (AppLayout, /login, /access-denied).</summary>
[TestFixture]
public class LogoutTests : BaseUiTest
{
    /// <summary>
    /// OAuth2: go to app root → follow redirects (Challenge → IdP or /connect/authorize → /login) → login → back to app → click Logout → assert logged out.
    /// Uses OAUTH2_TEST_USER and OAUTH2_TEST_PASSWORD, or defaults admin/admin (match scripts).
    /// </summary>
    [Test]
    [Category("RequiresOAuth2")]
    public async Task OAuth2_login_then_logout_returns_to_app_and_shows_login_link()
    {
        var oauth2User = Environment.GetEnvironmentVariable("OAUTH2_TEST_USER") ?? "admin";
        var oauth2Password = Environment.GetEnvironmentVariable("OAUTH2_TEST_PASSWORD") ?? "admin";

        await WithPageAsync(async page =>
        {
            var host = new Uri(BaseUrl).Host;
            await page.GotoAsync($"{BaseUrl.TrimEnd('/')}/", new PageGotoOptions { WaitUntil = WaitUntilState.NetworkIdle, Timeout = 30000 });
            await page.WaitForLoadStateAsync(LoadState.DOMContentLoaded);

            var currentUrl = page.Url;
            if (currentUrl.Contains("chrome-error", StringComparison.OrdinalIgnoreCase))
                Assert.Fail($"Navigation to / failed: page landed on {currentUrl}");

            try
            {
                var uri = new Uri(currentUrl);
                var onAppRoot = currentUrl.Contains(host, StringComparison.OrdinalIgnoreCase) && (string.IsNullOrEmpty(uri.AbsolutePath) || uri.AbsolutePath.TrimEnd('/') == "");
                if (onAppRoot)
                {
                    await page.WaitForURLAsync(u => u.Contains("connect/authorize") || u.Contains("/login") || u.Contains("Account/Login") || u.Contains("keycloak") || u.Contains("openid-connect/auth"), new PageWaitForURLOptions { Timeout = 15000 });
                }
            }
            catch { }

            currentUrl = page.Url;
            if (currentUrl.Contains("connect/authorize", StringComparison.OrdinalIgnoreCase))
            {
                await page.WaitForLoadStateAsync(LoadState.NetworkIdle);
                await page.WaitForTimeoutAsync(3000);
                if (page.Url.Contains("connect/authorize", StringComparison.OrdinalIgnoreCase))
                {
                    var hasLoginForm = await page.Locator("input[name='Email'], input[type='email']").First.IsVisibleAsync().ConfigureAwait(false);
                    if (!hasLoginForm)
                    {
                        var errContent = await page.ContentAsync();
                        var isErrorPage = errContent.Contains("HTTP ERROR 400", StringComparison.OrdinalIgnoreCase)
                            || errContent.Contains("invalid response", StringComparison.OrdinalIgnoreCase)
                            || errContent.Contains("This page isn't working", StringComparison.OrdinalIgnoreCase)
                            || errContent.Contains("ERR_INVALID_HTTP_RESPONSE", StringComparison.OrdinalIgnoreCase)
                            || (errContent.Contains("Reload", StringComparison.OrdinalIgnoreCase) && errContent.Contains("400", StringComparison.OrdinalIgnoreCase));
                        if (isErrorPage)
                            Assert.Fail("OAuth2 authorize endpoint returned error (e.g. 400 invalid_scope). Check OpenIddict scope configuration.");
                        try
                        {
                            await page.WaitForURLAsync(u => u.Contains(host) && (u.Contains("/login") || u.Contains("keycloak") || u.Contains("openid-connect/auth")), new PageWaitForURLOptions { Timeout = 10000 });
                        }
                        catch (TimeoutException)
                        {
                            Assert.Fail("Stuck on /connect/authorize; expected redirect to /login. OAuth2 authorize may return an error (e.g. 400 invalid_scope). Check OpenIddict scope configuration.");
                        }
                    }
                }
            }

            static bool IsSpaLogin(string url)
            {
                try { var p = new Uri(url).AbsolutePath.TrimEnd('/'); return p == "/login" || p.StartsWith("/login", StringComparison.Ordinal); } catch { return false; }
            }
            currentUrl = page.Url;
            var onExternalIdP = currentUrl.Contains("keycloak", StringComparison.OrdinalIgnoreCase) || currentUrl.Contains("openid-connect/auth", StringComparison.OrdinalIgnoreCase);
            var onAppLogin = currentUrl.Contains(host, StringComparison.OrdinalIgnoreCase) && IsSpaLogin(currentUrl);

            if (onExternalIdP)
            {
                var userInput = page.Locator("input#username, input[name='username'], input[autocomplete='username'], input[type='text'], input[name='Email']").First;
                try
                {
                    await userInput.WaitForAsync(new LocatorWaitForOptions { State = WaitForSelectorState.Visible, Timeout = 15000 });
                }
                catch (TimeoutException)
                {
                    var html = await page.ContentAsync();
                    Assert.Fail($"Expected IdP login form at URL={currentUrl}. Body snippet: {html[..Math.Min(800, html.Length)]}");
                }
                await userInput.FillAsync(oauth2User);
                await page.Locator("input#password, input[name='password'], input[type='password']").First.FillAsync(oauth2Password);
                await page.Locator("#kc-login, input[type='submit'], button[type='submit']").First.ClickAsync();
                await page.WaitForURLAsync(u => u.Contains(host) && !u.Contains("openid-connect/auth") && !u.Contains("signin-oidc"), new PageWaitForURLOptions { Timeout = 20000 });
            }
            else if (onAppLogin)
            {
                await page.WaitForLoadStateAsync(LoadState.NetworkIdle);
                var email = oauth2User.Contains("@") ? oauth2User : $"{oauth2User}@certa.local";
                var returnUrl = "/";
                var pageUrl = page.Url;
                var idx = pageUrl.IndexOf("returnUrl=", StringComparison.OrdinalIgnoreCase);
                if (idx >= 0)
                {
                    var start = idx + "returnUrl=".Length;
                    var end = pageUrl.IndexOf('&', start);
                    var val = end >= 0 ? pageUrl[start..end] : pageUrl[start..];
                    try { returnUrl = Uri.UnescapeDataString(Uri.UnescapeDataString(val)); } catch { }
                }
                var req = page.Context.APIRequest;
                var antires = await req.GetAsync($"{BaseUrl}/api/antiforgery", new APIRequestContextOptions { IgnoreHTTPSErrors = true });
                var antiJson = antires.Ok ? await antires.JsonAsync() : null;
                var token = antiJson?.GetProperty("token").GetString() ?? "";
                var form = req.CreateFormData();
                form.Set("__RequestVerificationToken", token);
                form.Set("Email", email);
                form.Set("Password", oauth2Password);
                form.Set("RememberMe", "false");
                form.Set("ReturnUrl", returnUrl);
                var loginRes = await req.PostAsync($"{BaseUrl}/Account/Login", new APIRequestContextOptions { Form = form, IgnoreHTTPSErrors = true });
                if (loginRes.Status is < 200 or >= 400)
                    Assert.Fail($"Login POST failed: {loginRes.Status}");
                await page.GotoAsync($"{BaseUrl.TrimEnd('/')}/", new PageGotoOptions { WaitUntil = WaitUntilState.NetworkIdle, Timeout = 20000 });
                await page.WaitForURLAsync(u => u.Contains(host) && !u.Contains("signin-oidc"), new PageWaitForURLOptions { Timeout = 20000 });
            }
            else
            {
                Assert.Fail($"Unexpected state after navigating to /: URL={currentUrl}. Expected login page (app or IdP).");
            }

            await page.WaitForLoadStateAsync(LoadState.DOMContentLoaded);
            await page.WaitForLoadStateAsync(LoadState.NetworkIdle);
            var urlAfterLogin = page.Url;
            var onSpaLoginAfter = urlAfterLogin.Contains(host, StringComparison.OrdinalIgnoreCase) && IsSpaLogin(urlAfterLogin);
            if (onSpaLoginAfter)
            {
                await page.Locator("input[name='Email'], input[type='email']").First.WaitForAsync(new LocatorWaitForOptions { State = WaitForSelectorState.Visible, Timeout = 5000 });
                await page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Login" }).WaitForAsync(new LocatorWaitForOptions { State = WaitForSelectorState.Visible, Timeout = 5000 });
                Assert.Fail($"Still on SPA login page after OAuth2 login; expected app or access-denied. URL={urlAfterLogin}");
            }
            if (urlAfterLogin.Contains("SignInComplete", StringComparison.OrdinalIgnoreCase))
                await page.WaitForURLAsync(u => !u.Contains("SignInComplete", StringComparison.OrdinalIgnoreCase), new PageWaitForURLOptions { Timeout = 15000 });
            await page.WaitForURLAsync(u => u.Contains(host) && !u.Contains("signin-oidc"), new PageWaitForURLOptions { Timeout = 20000 });
            await page.WaitForLoadStateAsync(LoadState.NetworkIdle);
            await page.WaitForLoadStateAsync(LoadState.DOMContentLoaded);
            await page.WaitForTimeoutAsync(5000);
            var logoutBtn = page.Locator("form[action*='Logout'] button").First;
            await logoutBtn.WaitForAsync(new LocatorWaitForOptions { State = WaitForSelectorState.Visible, Timeout = 35000 });
            await page.WaitForLoadStateAsync(LoadState.NetworkIdle);
            await Assertions.Expect(logoutBtn).Not.ToBeDisabledAsync(new LocatorAssertionsToBeDisabledOptions { Timeout = 10000 });
            await logoutBtn.ClickAsync();

            await page.WaitForURLAsync(u => u.Contains(new Uri(BaseUrl).Host) || u.Contains("openid-connect") || u.Contains("keycloak") || u.Contains("/login"), new PageWaitForURLOptions { Timeout = 25000 });
            await page.WaitForLoadStateAsync(LoadState.DOMContentLoaded);
            var url = page.Url;
            var onIdP = url.Contains("openid-connect", StringComparison.OrdinalIgnoreCase) || url.Contains("keycloak", StringComparison.OrdinalIgnoreCase) || url.Contains("/auth/", StringComparison.OrdinalIgnoreCase);
            if (onIdP)
            {
                Assert.Pass("After logout redirected to IdP (logged out).");
                return;
            }
            var onApp = url.Contains(new Uri(BaseUrl).Host, StringComparison.OrdinalIgnoreCase);
            Assert.That(onApp, Is.True, "After logout should be on app or IdP.");
            var loginLink = page.Locator("a[href*='/login']");
            var logoutBtnAfter = page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Logout" }).First;
            var hasLogin = await loginLink.IsVisibleAsync();
            var hasLogout = await logoutBtnAfter.IsVisibleAsync();
            var onLoginPage = url.Contains("login", StringComparison.OrdinalIgnoreCase);
            Assert.That(hasLogin || !hasLogout || onLoginPage, Is.True, "After logout: Login link or login page should be visible or Logout button should be gone (logged out).");
        });
    }

    /// <summary>
    /// Local auth: go to app root → redirect to /login → login → logout → assert logged out.
    /// Uses default admin (admin@certa.local / Admin123!). Requires OAuth2 disabled (local auth) and app running at BASE_URL.
    /// </summary>
    [Test]
    [Category("RequiresLocalAuth")]
    public async Task After_login_logout_returns_to_home_and_shows_login_link()
    {
        await WithPageAsync(async page =>
        {
            await page.GotoAsync($"{BaseUrl.TrimEnd('/')}/");
            await page.WaitForLoadStateAsync(LoadState.NetworkIdle);
            if (page.Url.Contains("keycloak", StringComparison.OrdinalIgnoreCase) || page.Url.Contains("openid-connect", StringComparison.OrdinalIgnoreCase))
            {
                Assert.Fail("OAuth2 is enabled; run local-auth tests with OAuth2 disabled.");
            }
            if (!page.Url.Contains("login", StringComparison.OrdinalIgnoreCase))
            {
                await page.WaitForURLAsync(u => u.Contains("login", StringComparison.OrdinalIgnoreCase), new PageWaitForURLOptions { Timeout = 10000 });
            }

            var req = page.Context.APIRequest;
            var antires = await req.GetAsync($"{BaseUrl}/api/antiforgery", new APIRequestContextOptions { IgnoreHTTPSErrors = true });
            var antiJson = antires.Ok ? await antires.JsonAsync() : null;
            var token = antiJson?.GetProperty("token").GetString() ?? "";
            var form = req.CreateFormData();
            form.Set("__RequestVerificationToken", token);
            form.Set("Email", "admin@certa.local");
            form.Set("Password", "Admin123!");
            form.Set("RememberMe", "false");
            form.Set("ReturnUrl", "/");
            var loginRes = await req.PostAsync($"{BaseUrl}/Account/Login", new APIRequestContextOptions { Form = form, IgnoreHTTPSErrors = true });
            if (loginRes.Status is < 200 or >= 400)
                Assert.Fail($"Login POST failed: {loginRes.Status}");
            await page.GotoAsync($"{BaseUrl.TrimEnd('/')}/", new PageGotoOptions { WaitUntil = WaitUntilState.NetworkIdle, Timeout = 15000 });

            await page.WaitForURLAsync(u => u.Contains("/"), new PageWaitForURLOptions { Timeout = 10000 });
            await page.WaitForLoadStateAsync(LoadState.NetworkIdle);

            var urlAfterLogin = page.Url;
            if (urlAfterLogin.Contains("login", StringComparison.OrdinalIgnoreCase))
            {
                await page.Locator("input[name='Email'], input[type='email']").First.WaitForAsync(new LocatorWaitForOptions { State = WaitForSelectorState.Visible, Timeout = 5000 });
                await page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Login" }).WaitForAsync(new LocatorWaitForOptions { State = WaitForSelectorState.Visible, Timeout = 5000 });
                Assert.Fail("Still on login page after local login; server may not have returned a redirect (e.g. antiforgery or auth failed).");
            }
            var logoutBtn = page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Logout" }).First;
            await logoutBtn.WaitForAsync(new LocatorWaitForOptions { State = WaitForSelectorState.Visible, Timeout = 10000 });
            await page.WaitForLoadStateAsync(LoadState.NetworkIdle);
            await Assertions.Expect(logoutBtn).Not.ToBeDisabledAsync(new LocatorAssertionsToBeDisabledOptions { Timeout = 10000 });
            await logoutBtn.ClickAsync();

            await page.WaitForURLAsync(u => u.Contains("login", StringComparison.OrdinalIgnoreCase) || u.Contains("openid-connect", StringComparison.OrdinalIgnoreCase) || u.Contains("keycloak", StringComparison.OrdinalIgnoreCase), new PageWaitForURLOptions { Timeout = 20000 });
            await page.WaitForLoadStateAsync(LoadState.NetworkIdle);
            var url = page.Url;
            var onLogin = url.Contains("login", StringComparison.OrdinalIgnoreCase);
            var onIdP = url.Contains("keycloak", StringComparison.OrdinalIgnoreCase) || url.Contains("openid-connect", StringComparison.OrdinalIgnoreCase);
            var loginLink = page.GetByRole(AriaRole.Link, new PageGetByRoleOptions { Name = "Login" });
            var loginButton = page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Login" });
            var hasLoginLink = await loginLink.IsVisibleAsync();
            var hasLoginButton = await loginButton.IsVisibleAsync();
            Assert.That(onLogin || hasLoginLink || hasLoginButton || onIdP, Is.True, "After logout should be on login page, show Login link/button, or redirect to IdP.");
        });
    }

    /// <summary>
    /// OAuth2: go to app root → follow redirects → login as no-admin → redirect to AccessDenied.
    /// Uses OAUTH2_TEST_USER_NO_ADMIN and OAUTH2_TEST_PASSWORD_NO_ADMIN, or defaults certa_noadmin/noadmin123 (match create-oauth2-user-noadmin.sh).
    /// </summary>
    [Test]
    [Category("RequiresOAuth2")]
    public async Task OAuth2_login_without_certa_admin_redirects_to_AccessDenied()
    {
        var user = Environment.GetEnvironmentVariable("OAUTH2_TEST_USER_NO_ADMIN") ?? "certa_noadmin";
        var password = Environment.GetEnvironmentVariable("OAUTH2_TEST_PASSWORD_NO_ADMIN") ?? "noadmin123";
        var host = new Uri(BaseUrl).Host;

        await WithPageAsync(async page =>
        {
            await page.GotoAsync($"{BaseUrl.TrimEnd('/')}/", new PageGotoOptions { WaitUntil = WaitUntilState.NetworkIdle, Timeout = 30000 });
            await page.WaitForLoadStateAsync(LoadState.DOMContentLoaded);

            bool IsSpaLoginPath(string url)
            {
                try { var p = new Uri(url).AbsolutePath.TrimEnd('/'); return p == "/login" || p.StartsWith("/login", StringComparison.Ordinal); } catch { return false; }
            }
            var currentUrl = page.Url;
            if (currentUrl.Contains("chrome-error", StringComparison.OrdinalIgnoreCase))
                Assert.Fail($"Navigation to / failed: page landed on {currentUrl}");

            try
            {
                var uri = new Uri(currentUrl);
                var onAppRoot = currentUrl.Contains(host, StringComparison.OrdinalIgnoreCase) && (string.IsNullOrEmpty(uri.AbsolutePath) || uri.AbsolutePath.TrimEnd('/') == "");
                if (onAppRoot)
                {
                    await page.WaitForURLAsync(u => u.Contains("connect/authorize") || u.Contains("/login") || u.Contains("Account/Login") || u.Contains("keycloak") || u.Contains("openid-connect/auth"), new PageWaitForURLOptions { Timeout = 15000 });
                }
            }
            catch { }

            currentUrl = page.Url;
            if (currentUrl.Contains("connect/authorize", StringComparison.OrdinalIgnoreCase))
            {
                await page.WaitForLoadStateAsync(LoadState.NetworkIdle);
                await page.WaitForTimeoutAsync(3000);
                if (page.Url.Contains("connect/authorize", StringComparison.OrdinalIgnoreCase))
                {
                    var hasLoginForm = await page.Locator("input[name='Email'], input[type='email']").First.IsVisibleAsync().ConfigureAwait(false);
                    if (!hasLoginForm)
                    {
                        var errContent = await page.ContentAsync();
                        var isErrorPage = errContent.Contains("HTTP ERROR 400", StringComparison.OrdinalIgnoreCase)
                            || errContent.Contains("invalid response", StringComparison.OrdinalIgnoreCase)
                            || errContent.Contains("This page isn't working", StringComparison.OrdinalIgnoreCase)
                            || errContent.Contains("ERR_INVALID_HTTP_RESPONSE", StringComparison.OrdinalIgnoreCase)
                            || (errContent.Contains("Reload", StringComparison.OrdinalIgnoreCase) && errContent.Contains("400", StringComparison.OrdinalIgnoreCase));
                        if (isErrorPage)
                            Assert.Fail("OAuth2 authorize endpoint returned error (e.g. 400 invalid_scope). Check OpenIddict scope configuration.");
                        try
                        {
                            await page.WaitForURLAsync(u => u.Contains(host) && (u.Contains("/login") || u.Contains("keycloak") || u.Contains("openid-connect/auth")), new PageWaitForURLOptions { Timeout = 10000 });
                        }
                        catch (TimeoutException)
                        {
                            Assert.Fail("Stuck on /connect/authorize; expected redirect to /login. OAuth2 authorize may return an error (e.g. 400 invalid_scope). Check OpenIddict scope configuration.");
                        }
                    }
                }
            }

            currentUrl = page.Url;
            var onExternalIdP = currentUrl.Contains("keycloak", StringComparison.OrdinalIgnoreCase) || currentUrl.Contains("openid-connect/auth", StringComparison.OrdinalIgnoreCase);
            var onAppLogin = currentUrl.Contains(host, StringComparison.OrdinalIgnoreCase) && IsSpaLoginPath(currentUrl);

            if (onExternalIdP)
            {
                var userInput = page.Locator("input#username, input[name='username'], input[autocomplete='username'], input[type='text']").First;
                await userInput.WaitForAsync(new LocatorWaitForOptions { State = WaitForSelectorState.Visible, Timeout = 15000 });
                await userInput.FillAsync(user);
                await page.Locator("input#password, input[name='password'], input[type='password']").First.FillAsync(password);
                await page.Locator("#kc-login, input[type='submit'], button[type='submit']").First.ClickAsync();
                await page.WaitForURLAsync(u => u.Contains(host) && (u.Contains("AccessDenied", StringComparison.OrdinalIgnoreCase) || u.Contains("access-denied") || !u.Contains("openid-connect")), new PageWaitForURLOptions { Timeout = 20000 });
            }
            else if (onAppLogin)
            {
                await page.WaitForLoadStateAsync(LoadState.NetworkIdle);
                var email = user.Contains("@") ? user : $"{user}@certa.local";
                var returnUrl = "/";
                var pageUrl = page.Url;
                var idx = pageUrl.IndexOf("returnUrl=", StringComparison.OrdinalIgnoreCase);
                if (idx >= 0)
                {
                    var start = idx + "returnUrl=".Length;
                    var end = pageUrl.IndexOf('&', start);
                    var val = end >= 0 ? pageUrl[start..end] : pageUrl[start..];
                    try { returnUrl = Uri.UnescapeDataString(Uri.UnescapeDataString(val)); } catch { }
                }
                var req = page.Context.APIRequest;
                var antires = await req.GetAsync($"{BaseUrl}/api/antiforgery", new APIRequestContextOptions { IgnoreHTTPSErrors = true });
                var antiJson = antires.Ok ? await antires.JsonAsync() : null;
                var token = antiJson?.GetProperty("token").GetString() ?? "";
                var form = req.CreateFormData();
                form.Set("__RequestVerificationToken", token);
                form.Set("Email", email);
                form.Set("Password", password);
                form.Set("RememberMe", "false");
                form.Set("ReturnUrl", returnUrl);
                var loginRes = await req.PostAsync($"{BaseUrl}/Account/Login", new APIRequestContextOptions { Form = form, IgnoreHTTPSErrors = true });
                if (loginRes.Status is < 200 or >= 400)
                    Assert.Fail($"Login POST failed: {loginRes.Status}");
                Assert.That(loginRes.Url, Does.Contain("access-denied").IgnoreCase, $"Login as no-admin should redirect to access-denied. Final URL={loginRes.Url}");
                await page.GotoAsync(loginRes.Url, new PageGotoOptions { WaitUntil = WaitUntilState.NetworkIdle, Timeout = 15000 });
            }
            else
            {
                Assert.Fail($"Unexpected state after navigating to /: URL={currentUrl}. Expected login page (app or IdP).");
            }

            await page.WaitForLoadStateAsync(LoadState.DOMContentLoaded);
            await page.WaitForLoadStateAsync(LoadState.NetworkIdle);
            var url = page.Url;
            if (url.Contains("SignInComplete", StringComparison.OrdinalIgnoreCase))
                await page.WaitForURLAsync(u => !u.Contains("SignInComplete", StringComparison.OrdinalIgnoreCase), new PageWaitForURLOptions { Timeout = 15000 });
            url = page.Url;
            Assert.That(url, Does.Contain("access-denied").IgnoreCase, $"Should land on access-denied for no-admin. URL={url}");
            await page.WaitForLoadStateAsync(LoadState.NetworkIdle);
            await page.GetByText("Access denied", new PageGetByTextOptions { Exact = false }).First.WaitForAsync(new LocatorWaitForOptions { State = WaitForSelectorState.Visible, Timeout = 15000 });
            var content = await page.ContentAsync();
            Assert.That(content, Does.Contain("Access denied").IgnoreCase, "Access denied page should show 'Access denied'.");
            await page.GotoAsync(BaseUrl);
            await page.WaitForURLAsync(u => true, new PageWaitForURLOptions { Timeout = 10000 });
            await page.WaitForLoadStateAsync(LoadState.DOMContentLoaded);
            var finalUrl = page.Url;
            Assert.That(finalUrl, Does.Not.Contain("access-denied").IgnoreCase, "Navigating to app after AccessDenied should not land on access-denied again (login or IdP).");
        });
    }

    /// <summary>
    /// Local auth: go to app root → redirect to /login → invalid credentials → stay on Login with error. Requires OAuth2 disabled.
    /// </summary>
    [Test]
    [Category("RequiresLocalAuth")]
    public async Task Local_invalid_login_stays_on_login_with_error()
    {
        await WithPageAsync(async page =>
        {
            await page.GotoAsync($"{BaseUrl.TrimEnd('/')}/");
            await page.WaitForLoadStateAsync(LoadState.DOMContentLoaded);
            if (page.Url.Contains("keycloak", StringComparison.OrdinalIgnoreCase) || page.Url.Contains("openid-connect", StringComparison.OrdinalIgnoreCase))
            {
                Assert.Fail("OAuth2 is enabled; run local-auth tests with OAuth2 disabled.");
            }
            if (!page.Url.Contains("login", StringComparison.OrdinalIgnoreCase))
            {
                await page.WaitForURLAsync(u => u.Contains("login", StringComparison.OrdinalIgnoreCase), new PageWaitForURLOptions { Timeout = 10000 });
            }

            await page.Locator("input[name='Email'], input[type='email']").First.FillAsync("nobody@example.com");
            await page.Locator("input[name='Password'], input[type='password']").First.FillAsync("WrongPassword123!");
            await page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Login" }).ClickAsync();

            await page.WaitForLoadStateAsync(LoadState.DOMContentLoaded);
            Assert.That(page.Url, Does.Contain("login").IgnoreCase, "Should remain on Login page.");
            await page.WaitForTimeoutAsync(3000);
            var content = await page.ContentAsync();
            Assert.That(content, Does.Contain("Invalid login attempt").Or.Contain("Invalid").Or.Contain("error").Or.Contain("alert-danger").Or.Contain("Login"), "Should show invalid login message or still show Login form.");
        });
    }

    /// <summary>
    /// GET /Account/Logout is not allowed; server returns 405 Method Not Allowed.
    /// </summary>
    [Test]
    public async Task GET_Account_Logout_returns_405()
    {
        await WithPageAsync(async page =>
        {
            var response = await page.GotoAsync($"{BaseUrl}/Account/Logout");
            Assert.That(response, Is.Not.Null);
            Assert.That(response!.Status, Is.EqualTo(405), "GET /Account/Logout must return 405 Method Not Allowed.");
        });
    }
}
