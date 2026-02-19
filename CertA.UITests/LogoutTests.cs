using Microsoft.Playwright;
using NUnit.Framework;

namespace CertA.UITests;

[TestFixture]
public class LogoutTests : BaseUiTest
{
    /// <summary>
    /// OAuth2/Keycloak: go to app → Keycloak login → back to app → click Logout → assert logged out.
    /// Set KEYCLOAK_TEST_USER and KEYCLOAK_TEST_PASSWORD (Keycloak user with certa admin role).
    /// </summary>
    [Test]
    [Category("RequiresKeycloak")]
    public async Task OAuth2_login_then_logout_returns_to_app_and_shows_login_link()
    {
        var keycloakUser = Environment.GetEnvironmentVariable("KEYCLOAK_TEST_USER");
        var keycloakPassword = Environment.GetEnvironmentVariable("KEYCLOAK_TEST_PASSWORD");
        if (string.IsNullOrEmpty(keycloakUser) || string.IsNullOrEmpty(keycloakPassword))
        {
            Assert.Ignore("KEYCLOAK_TEST_USER and KEYCLOAK_TEST_PASSWORD must be set for this test.");
        }

        await WithPageAsync(async page =>
        {
            await page.GotoAsync(BaseUrl, new PageGotoOptions { WaitUntil = WaitUntilState.DOMContentLoaded, Timeout = 60000 });
            await page.WaitForLoadStateAsync(LoadState.Load);

            var currentUrl = page.Url;
            if (currentUrl.Contains("auth", StringComparison.OrdinalIgnoreCase) || currentUrl.Contains("keycloak", StringComparison.OrdinalIgnoreCase) || currentUrl.Contains("openid-connect"))
            {
                await page.Locator("input#username, input[name='username']").First.WaitForAsync(new LocatorWaitForOptions { State = WaitForSelectorState.Visible, Timeout = 10000 });
                await page.Locator("input#username, input[name='username']").First.FillAsync(keycloakUser);
                await page.Locator("input#password, input[name='password']").First.FillAsync(keycloakPassword);
                await page.Locator("#kc-login, input[type='submit']").First.ClickAsync();
                await page.WaitForURLAsync(u => u.Contains(new Uri(BaseUrl).Host) && !u.Contains("openid-connect/auth"), new PageWaitForURLOptions { Timeout = 20000 });
            }

            await page.WaitForLoadStateAsync(LoadState.DOMContentLoaded);
            var dropdown = page.Locator("a.dropdown-toggle").First;
            if (await dropdown.IsVisibleAsync())
            {
                await dropdown.ClickAsync();
                await page.WaitForTimeoutAsync(300);
            }
            await page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Logout" }).WaitForAsync(new LocatorWaitForOptions { State = WaitForSelectorState.Visible, Timeout = 5000 });
            await page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Logout" }).First.ClickAsync();

            await page.WaitForURLAsync(u => u.Contains(new Uri(BaseUrl).Host) || u.Contains("openid-connect") || u.Contains("keycloak"), new PageWaitForURLOptions { Timeout = 25000 });
            await page.WaitForLoadStateAsync(LoadState.DOMContentLoaded);
            var url = page.Url;
            var onKeycloak = url.Contains("openid-connect", StringComparison.OrdinalIgnoreCase) || url.Contains("keycloak", StringComparison.OrdinalIgnoreCase) || url.Contains("/auth/", StringComparison.OrdinalIgnoreCase);
            if (onKeycloak)
            {
                Assert.Pass("After logout redirected to IdP (logged out).");
                return;
            }
            var onApp = url.Contains(new Uri(BaseUrl).Host, StringComparison.OrdinalIgnoreCase);
            Assert.That(onApp, Is.True, "After logout should be on app or Keycloak.");
            var loginLink = page.Locator("a[href*='/Account/Login']");
            var userDropdown = page.Locator("a.dropdown-toggle").First;
            var hasLogin = await loginLink.IsVisibleAsync();
            var hasDropdown = await userDropdown.IsVisibleAsync();
            Assert.That(hasLogin || !hasDropdown, Is.True, "After logout: Login link should be visible or user dropdown should be gone (logged out).");
        });
    }

    /// <summary>
    /// Uses default admin (admin@certa.local / Admin123!). Requires Keycloak disabled (local auth) and app running at BASE_URL.
    /// </summary>
    [Test]
    [Category("RequiresLocalAuth")]
    public async Task After_login_logout_returns_to_home_and_shows_login_link()
    {
        await WithPageAsync(async page =>
        {
            await page.GotoAsync($"{BaseUrl}/Account/Login");
            await page.WaitForLoadStateAsync(LoadState.NetworkIdle);
            if (page.Url.Contains("keycloak", StringComparison.OrdinalIgnoreCase) || page.Url.Contains("openid-connect", StringComparison.OrdinalIgnoreCase))
            {
                Assert.Ignore("Keycloak is enabled; local login not available.");
            }

            await page.GetByLabel("Email", new PageGetByLabelOptions { Exact = true }).FillAsync("admin@certa.local");
            await page.GetByLabel("Password").FillAsync("Admin123!");
            await page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Login" }).ClickAsync();

            await page.WaitForURLAsync(u => u.Contains("/") && !u.Contains("Login"), new PageWaitForURLOptions { Timeout = 5000 });
            await page.WaitForLoadStateAsync(LoadState.NetworkIdle);

            await page.Locator("a.dropdown-toggle").First.ClickAsync();
            await page.WaitForTimeoutAsync(300);
            await page.Locator("form[action*='Logout'] button[type='submit']").First.ClickAsync();

            await page.WaitForLoadStateAsync(LoadState.NetworkIdle);
            var loginLink = page.GetByRole(AriaRole.Link, new PageGetByRoleOptions { Name = "Login" });
            await Assertions.Expect(loginLink).ToBeVisibleAsync(new LocatorAssertionsToBeVisibleOptions { Timeout = 5000 });
        });
    }

    /// <summary>
    /// OAuth2/Keycloak: user without certa admin role logs in at Keycloak → callback fails → redirect to AccessDenied.
    /// Set KEYCLOAK_TEST_USER_NO_ADMIN and KEYCLOAK_TEST_PASSWORD_NO_ADMIN (Keycloak user without certa client role admin).
    /// </summary>
    [Test]
    [Category("RequiresKeycloak")]
    public async Task OAuth2_login_without_certa_admin_redirects_to_AccessDenied()
    {
        var user = Environment.GetEnvironmentVariable("KEYCLOAK_TEST_USER_NO_ADMIN");
        var password = Environment.GetEnvironmentVariable("KEYCLOAK_TEST_PASSWORD_NO_ADMIN");
        if (string.IsNullOrEmpty(user) || string.IsNullOrEmpty(password))
        {
            Assert.Ignore("KEYCLOAK_TEST_USER_NO_ADMIN and KEYCLOAK_TEST_PASSWORD_NO_ADMIN must be set for this test.");
        }

        await WithPageAsync(async page =>
        {
            await page.GotoAsync(BaseUrl, new PageGotoOptions { WaitUntil = WaitUntilState.DOMContentLoaded, Timeout = 60000 });
            await page.WaitForLoadStateAsync(LoadState.Load);

            var currentUrl = page.Url;
            if (currentUrl.Contains("auth", StringComparison.OrdinalIgnoreCase) || currentUrl.Contains("keycloak", StringComparison.OrdinalIgnoreCase) || currentUrl.Contains("openid-connect"))
            {
                await page.Locator("input#username, input[name='username']").First.WaitForAsync(new LocatorWaitForOptions { State = WaitForSelectorState.Visible, Timeout = 10000 });
                await page.Locator("input#username, input[name='username']").First.FillAsync(user);
                await page.Locator("input#password, input[name='password']").First.FillAsync(password);
                await page.Locator("#kc-login, input[type='submit']").First.ClickAsync();
                await page.WaitForURLAsync(u => u.Contains(new Uri(BaseUrl).Host) && (u.Contains("AccessDenied", StringComparison.OrdinalIgnoreCase) || !u.Contains("openid-connect")), new PageWaitForURLOptions { Timeout = 20000 });
            }

            await page.WaitForLoadStateAsync(LoadState.DOMContentLoaded);
            var url = page.Url;
            Assert.That(url, Does.Contain("AccessDenied").IgnoreCase, "Should land on AccessDenied when user has no certa admin role.");
            var content = await page.ContentAsync();
            Assert.That(content, Does.Contain("Access denied").IgnoreCase, "AccessDenied page should show 'Access denied'.");

            await page.Locator("form[action*='Logout'] button[type='submit']").First.WaitForAsync(new LocatorWaitForOptions { State = WaitForSelectorState.Visible, Timeout = 5000 });
            await page.Locator("form[action*='Logout'] button[type='submit']").First.ClickAsync();

            await page.WaitForURLAsync(u => u.Contains(new Uri(BaseUrl).Host) || u.Contains("openid-connect") || u.Contains("keycloak"), new PageWaitForURLOptions { Timeout = 15000 });
            await page.WaitForLoadStateAsync(LoadState.DOMContentLoaded);
            var afterUrl = page.Url;
            Assert.That(afterUrl, Does.Not.Contain("AccessDenied").IgnoreCase, "After logout should not still be on AccessDenied (logout must run; if rejected, we bounce back here).");

            await page.GotoAsync(BaseUrl);
            await page.WaitForURLAsync(u => true, new PageWaitForURLOptions { Timeout = 10000 });
            await page.WaitForLoadStateAsync(LoadState.DOMContentLoaded);
            var finalUrl = page.Url;
            Assert.That(finalUrl, Does.Not.Contain("AccessDenied").IgnoreCase, "Navigating back to app after logout must not land on AccessDenied (confirms Keycloak session was cleared).");
        });
    }

    /// <summary>
    /// Local auth: invalid credentials → stay on Login with error. Requires Keycloak disabled.
    /// </summary>
    [Test]
    [Category("RequiresLocalAuth")]
    public async Task Local_invalid_login_stays_on_login_with_error()
    {
        await WithPageAsync(async page =>
        {
            await page.GotoAsync($"{BaseUrl}/Account/Login");
            await page.WaitForLoadStateAsync(LoadState.DOMContentLoaded);
            if (page.Url.Contains("keycloak", StringComparison.OrdinalIgnoreCase) || page.Url.Contains("openid-connect", StringComparison.OrdinalIgnoreCase))
            {
                Assert.Ignore("Keycloak is enabled; local login not available.");
            }

            await page.GetByLabel("Email", new PageGetByLabelOptions { Exact = true }).FillAsync("nobody@example.com");
            await page.GetByLabel("Password").FillAsync("WrongPassword123!");
            await page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Login" }).ClickAsync();

            await page.WaitForLoadStateAsync(LoadState.DOMContentLoaded);
            Assert.That(page.Url, Does.Contain("Login").IgnoreCase, "Should remain on Login page.");
            var content = await page.ContentAsync();
            Assert.That(content, Does.Contain("Invalid login attempt").Or.Contain("Invalid").Or.Contain("error"), "Should show invalid login message.");
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
