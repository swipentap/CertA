using Microsoft.Playwright;
using NUnit.Framework;

namespace CertA.UITests;

/// <summary>Smoke tests for home and login. App is SPA-only; assertions accept SPA or IdP redirect.</summary>
[TestFixture]
public class SmokeTests : BaseUiTest
{
    [Test]
    public async Task Home_page_loads_or_redirects()
    {
        await WithPageAsync(async page =>
        {
            var response = await page.GotoAsync(BaseUrl);
            Assert.That(response, Is.Not.Null);
            Assert.That(response!.Status, Is.LessThan(500),
                "Home should not return 5xx (server error)");
            await page.WaitForLoadStateAsync(LoadState.NetworkIdle);
            var content = await page.ContentAsync();
            Assert.That(content, Does.Contain("CertA").Or.Contain("keycloak").Or.Contain("openid-connect").Or.Contain("sign in"),
                "Page should show app name or auth (OAuth2/local login)");
        });
    }

    [Test]
    public async Task Login_page_loads_or_redirects()
    {
        await WithPageAsync(async page =>
        {
            var response = await page.GotoAsync($"{BaseUrl}/login");
            Assert.That(response, Is.Not.Null);
            Assert.That(response!.Status, Is.LessThan(500));
            await page.WaitForLoadStateAsync(LoadState.NetworkIdle);
            var content = await page.ContentAsync();
            var hasEmailInput = await page.Locator("input[name='Email'], input[type='email']").CountAsync() > 0;
            var hasAuthContent = content.Contains("CertA", StringComparison.OrdinalIgnoreCase) || content.Contains("sign in", StringComparison.OrdinalIgnoreCase) || content.Contains("openid-connect", StringComparison.OrdinalIgnoreCase) || content.Contains("keycloak", StringComparison.OrdinalIgnoreCase) || content.Contains("login", StringComparison.OrdinalIgnoreCase);
            Assert.That(hasEmailInput || hasAuthContent, Is.True, "SPA login page should have email input or auth content (OAuth2/local)");
        });
    }
}
