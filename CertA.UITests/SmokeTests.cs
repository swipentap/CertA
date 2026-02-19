using Microsoft.Playwright;
using NUnit.Framework;

namespace CertA.UITests;

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
            Assert.That(content, Does.Contain("CertA").Or.Contain("keycloak").Or.Contain("sign in"),
                "Page should show app name or auth (Keycloak/local login)");
        });
    }

    [Test]
    public async Task Login_page_loads_or_redirects()
    {
        await WithPageAsync(async page =>
        {
            var response = await page.GotoAsync($"{BaseUrl}/Account/Login");
            Assert.That(response, Is.Not.Null);
            Assert.That(response!.Status, Is.LessThan(500));
            await page.WaitForLoadStateAsync(LoadState.NetworkIdle);
            var content = await page.ContentAsync();
            var hasEmailInput = await page.Locator("input[name='Email']").CountAsync() > 0;
            var hasAuthContent = content.Contains("CertA", StringComparison.OrdinalIgnoreCase) || content.Contains("sign in", StringComparison.OrdinalIgnoreCase) || content.Contains("keycloak", StringComparison.OrdinalIgnoreCase) || content.Contains("login", StringComparison.OrdinalIgnoreCase);
            Assert.That(hasEmailInput || hasAuthContent, Is.True, "Login page should have email input or auth content");
        });
    }
}
