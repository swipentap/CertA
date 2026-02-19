using NUnit.Framework;
using System.Net.Http;

namespace CertA.Tests.Acme;

/// <summary>
/// Integration tests that require a running CertA instance with database.
/// Run with: dotnet run (in CertA) then dotnet test --filter "FullyQualifiedName~AcmeDirectoryIntegrationTests"
/// Or set BASE_URL to point to a deployed instance.
/// </summary>
[TestFixture]
[Explicit("Requires running CertA with database")]
public class AcmeDirectoryIntegrationTests
{
    private static readonly string BaseUrl = Environment.GetEnvironmentVariable("CERTA_BASE_URL") ?? "http://localhost:5000";

    [Test]
    public async Task GetDirectory_ReturnsValidJson()
    {
        using var client = new HttpClient();
        var response = await client.GetAsync($"{BaseUrl}/acme/directory");
        response.EnsureSuccessStatusCode();
        var json = await response.Content.ReadAsStringAsync();
        Assert.That(json, Does.Contain("newNonce"));
        Assert.That(json, Does.Contain("newAccount"));
        Assert.That(json, Does.Contain("newOrder"));
    }

    [Test]
    public async Task GetNewNonce_Returns204WithNonce()
    {
        using var client = new HttpClient();
        var response = await client.GetAsync($"{BaseUrl}/acme/newNonce");
        Assert.That((int)response.StatusCode, Is.EqualTo(204));
        Assert.That(response.Headers.Contains("Replay-Nonce"), Is.True);
    }
}
