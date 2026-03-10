using Microsoft.Playwright;
using NUnit.Framework;

namespace CertA.UITests;

/// <summary>
/// E2E tests for the Vue/Pinia/Tabler SPA. App must be running at BASE_URL (default https://localhost:8443).
/// </summary>
[TestFixture]
public class SpaTests : BaseUiTest
{
    [Test]
    public async Task SPA_home_loads_and_shows_CertA()
    {
        await WithPageAsync(async page =>
        {
            var response = await page.GotoAsync(BaseUrl, new PageGotoOptions { WaitUntil = WaitUntilState.DOMContentLoaded, Timeout = 15000 });
            Assert.That(response, Is.Not.Null);
            Assert.That(response!.Status, Is.LessThan(500));
            await page.WaitForLoadStateAsync(LoadState.NetworkIdle);
            var content = await page.ContentAsync();
            Assert.That(content, Does.Contain("CertA").Or.Contain("openid-connect").Or.Contain("keycloak").Or.Contain("sign in").IgnoreCase,
                "SPA should show app name or redirect to IdP (OAuth2 on)");
        });
    }

    [Test]
    public async Task SPA_login_page_has_email_and_password()
    {
        await WithPageAsync(async page =>
        {
            await page.GotoAsync($"{BaseUrl.TrimEnd('/')}/", new PageGotoOptions { WaitUntil = WaitUntilState.DOMContentLoaded, Timeout = 15000 });
            await page.WaitForLoadStateAsync(LoadState.NetworkIdle);
            var baseHost = new Uri(BaseUrl).Host;
            try
            {
                var uri = new Uri(page.Url);
                var onAppRoot = page.Url.Contains(baseHost, StringComparison.OrdinalIgnoreCase) && (string.IsNullOrEmpty(uri.AbsolutePath) || uri.AbsolutePath.TrimEnd('/') == "");
                if (onAppRoot)
                {
                    await page.WaitForURLAsync(u => u.Contains("connect/authorize") || u.Contains("/login") || u.Contains("Account/Login") || u.Contains("keycloak") || u.Contains("openid-connect/auth"), new PageWaitForURLOptions { Timeout = 15000 });
                }
            }
            catch { }
            if (page.Url.Contains("keycloak", StringComparison.OrdinalIgnoreCase) || page.Url.Contains("openid-connect/auth", StringComparison.OrdinalIgnoreCase))
            {
                Assert.Inconclusive("Redirected to external IdP; cannot assert SPA login form. Run with OAuth2 disabled or embedded.");
            }
            if (page.Url.Contains("connect/authorize", StringComparison.OrdinalIgnoreCase))
            {
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
                            await page.WaitForURLAsync(u => u.Contains("/login") || u.Contains("keycloak") || u.Contains("openid-connect/auth"), new PageWaitForURLOptions { Timeout = 10000 });
                        }
                        catch (TimeoutException)
                        {
                            Assert.Fail("Stuck on /connect/authorize; expected redirect to /login. OAuth2 authorize may return an error (e.g. 400 invalid_scope). Check OpenIddict scope configuration.");
                        }
                    }
                }
            }
            if (!page.Url.Contains("login", StringComparison.OrdinalIgnoreCase))
            {
                await page.WaitForURLAsync(u => u.Contains("login", StringComparison.OrdinalIgnoreCase) || u.Contains("keycloak", StringComparison.OrdinalIgnoreCase) || u.Contains("openid-connect", StringComparison.OrdinalIgnoreCase), new PageWaitForURLOptions { Timeout = 10000 });
            }
            var email = page.Locator("input[name='Email'], input[type='email']").First;
            var password = page.Locator("input[name='Password'], input[type='password']").First;
            await Assertions.Expect(email).ToBeVisibleAsync(new LocatorAssertionsToBeVisibleOptions { Timeout = 5000 });
            await Assertions.Expect(password).ToBeVisibleAsync(new LocatorAssertionsToBeVisibleOptions { Timeout = 5000 });
            var loginBtn = page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Login" });
            await Assertions.Expect(loginBtn).ToBeVisibleAsync(new LocatorAssertionsToBeVisibleOptions { Timeout = 2000 });
        });
    }

    [Test]
    [Category("RequiresLocalAuth")]
    public async Task SPA_local_login_then_logout()
    {
        await WithPageAsync(async page =>
        {
            await page.GotoAsync($"{BaseUrl.TrimEnd('/')}/", new PageGotoOptions { WaitUntil = WaitUntilState.DOMContentLoaded, Timeout = 15000 });
            await page.WaitForLoadStateAsync(LoadState.NetworkIdle);
            if (page.Url.Contains("keycloak", StringComparison.OrdinalIgnoreCase) || page.Url.Contains("openid-connect", StringComparison.OrdinalIgnoreCase))
            {
                Assert.Fail("OAuth2 is enabled; run this test with OAuth2 disabled.");
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

            await page.WaitForURLAsync(u => true, new PageWaitForURLOptions { Timeout = 10000 });
            await page.WaitForLoadStateAsync(LoadState.DOMContentLoaded);

            var url = page.Url;
            if (url.Contains("login", StringComparison.OrdinalIgnoreCase))
            {
                await page.Locator("input[name='Email'], input[type='email']").First.WaitForAsync(new LocatorWaitForOptions { State = WaitForSelectorState.Visible, Timeout = 5000 });
                await page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Login" }).WaitForAsync(new LocatorWaitForOptions { State = WaitForSelectorState.Visible, Timeout = 5000 });
                Assert.Fail("After login still on login page. POST /Account/Login did not return a redirect (e.g. 302); response was 200 or 4xx, so SPA did not navigate.");
            }
            Assert.That(url, Does.Contain(new Uri(BaseUrl).Host), "After login should be on app");
            await Assertions.Expect(page.Locator(".navbar").First).ToBeVisibleAsync(new LocatorAssertionsToBeVisibleOptions { Timeout = 10000 });

            var logoutBtn = page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Logout" }).First;
            await logoutBtn.WaitForAsync(new LocatorWaitForOptions { State = WaitForSelectorState.Visible, Timeout = 10000 });
            await logoutBtn.ClickAsync();

            await page.WaitForURLAsync(_ => true, new PageWaitForURLOptions { Timeout = 10000 });
            await page.WaitForLoadStateAsync(LoadState.DOMContentLoaded);
            var afterUrl = page.Url;
            Assert.That(afterUrl, Does.Contain("login").Or.Contain(new Uri(BaseUrl).Host), "After logout should be on login or app");
        });
    }

    [Test]
    public async Task SPA_GET_Account_Logout_returns_405()
    {
        await WithPageAsync(async page =>
        {
            var response = await page.GotoAsync($"{BaseUrl}/Account/Logout");
            Assert.That(response, Is.Not.Null);
            Assert.That(response!.Status, Is.EqualTo(405));
        });
    }
}
