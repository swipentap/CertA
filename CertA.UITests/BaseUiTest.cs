using Microsoft.Playwright;

namespace CertA.UITests;

/// <summary>
/// Base for UI tests: runs against a running CertA instance (see README). Set BASE_URL or use default https://localhost:8443.
/// </summary>
public abstract class BaseUiTest : IDisposable
{
    protected static string BaseUrl { get; } =
        Environment.GetEnvironmentVariable("BASE_URL")?.TrimEnd('/') ?? "https://localhost:8443";

    protected async Task WithPageAsync(Func<IPage, Task> run)
    {
        var playwright = await Playwright.CreateAsync();
        var browser = await playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions { Headless = true });
        var context = await browser.NewContextAsync(new BrowserNewContextOptions { IgnoreHTTPSErrors = true });
        var page = await context.NewPageAsync();
        try
        {
            await run(page);
        }
        finally
        {
            await page.CloseAsync();
            await context.DisposeAsync();
            await browser.CloseAsync();
        }
    }

    public void Dispose() { }
}
