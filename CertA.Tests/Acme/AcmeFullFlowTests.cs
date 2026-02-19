using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using CertA.Data;
using CertA.Models.Acme;
using CertA.Options;
using CertA.Services;
using CertA.Services.Acme;
using CertA.Tests.Acme.Fakes;
using CertA.Tests.Acme.TestHelpers;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;

namespace CertA.Tests.Acme;

[TestFixture]
public class AcmeFullFlowTests
{
    private const string BaseUrl = "https://acme.test";
    private FakeAcmeStorageService _storage = null!;
    private ChallengeHttpHandler _httpHandler = null!;
    private IAcmeService _acmeService = null!;
    private RSA _accountKey = null!;
    private string _accountId = null!;
    private string _orderId = null!;
    private string _finalizeUrl = null!;

    [SetUp]
    public void SetUp()
    {
        _storage = new FakeAcmeStorageService();
        _httpHandler = new ChallengeHttpHandler();
        var httpClient = new HttpClient(_httpHandler) { BaseAddress = new Uri("http://test") };
        var httpFactory = new MockHttpClientFactory(httpClient);
        var options = Microsoft.Extensions.Options.Options.Create(new AcmeOptions
        {
            Enabled = true,
            DirectoryBaseUrl = BaseUrl,
            SystemUserId = "test-user-id",
            HttpChallengeTimeoutSeconds = 5
        });
        _acmeService = new AcmeService(
            _storage,
            new MockCertificateAuthorityService(),
            new MockAcmeCertificatePersistence(),
            httpFactory,
            options,
            new MockUserService("test-user-id"),
            NullLogger<AcmeService>.Instance
        );
        _accountKey = RSA.Create(2048);
    }

    [TearDown]
    public void TearDown()
    {
        _accountKey?.Dispose();
        _httpHandler?.Dispose();
    }

    [Test]
    public async Task FullFlow_NewAccount_NewOrder_ValidateChallenge_Finalize_GetCertificate()
    {
        // 1. NewAccount
        var nonce1 = await _acmeService.CreateNonceAsync();
        var jwkJson = JwsBuilder.RsaJwkToJson(_accountKey);
        var body1 = JwsBuilder.BuildJws(_accountKey, BaseUrl + "/acme/newAccount", "{}", nonce1, jwkJson: jwkJson);
        var (account, location) = await _acmeService.NewAccountAsync(StreamFrom(body1), BaseUrl + "/acme/newAccount");
        Assert.That(location, Is.Not.Null.And.Not.Empty);
        _accountId = location!.TrimEnd('/').Split('/').Last();
        Assert.That(_accountId, Does.StartWith("acct_"));

        // 2. NewOrder
        var nonce2 = await _acmeService.CreateNonceAsync();
        var kid = BaseUrl + "/acme/acct/" + _accountId;
        var identifiersPayload = """{"identifiers":[{"type":"dns","value":"test.example.com"}]}""";
        var body2 = JwsBuilder.BuildJws(_accountKey, BaseUrl + "/acme/newOrder", identifiersPayload, nonce2, kid: kid);
        var orderObj = await _acmeService.NewOrderAsync(StreamFrom(body2), BaseUrl + "/acme/newOrder");
        var orderJson = JsonSerializer.Serialize(orderObj);
        using var orderDoc = JsonDocument.Parse(orderJson);
        var root = orderDoc.RootElement;
        var authUrls = root.GetProperty("authorizations");
        var firstAuthUrl = authUrls[0].GetString();
        _finalizeUrl = root.GetProperty("finalize").GetString()!;
        var finalizeParts = _finalizeUrl!.TrimEnd('/').Split('/');
        _orderId = finalizeParts.Length >= 2 ? finalizeParts[^2] : "";
        Assert.That(firstAuthUrl, Is.Not.Null.And.Not.Empty);
        var authId = firstAuthUrl!.TrimEnd('/').Split('/').Last();

        var auths = await _storage.GetAuthorizationsForOrderAsync(_orderId);
        Assert.That(auths, Has.Count.GreaterThanOrEqualTo(1));
        var challenges = await _storage.GetChallengesForAuthAsync(authId);
        Assert.That(challenges, Has.Count.GreaterThanOrEqualTo(1));
        var challenge = challenges[0];

        _httpHandler.SetKeyAuthorization(challenge.KeyAuthorization);

        // 3. Validate HTTP-01 challenge
        var challengeResult = await _acmeService.HandleChallengeAsync(challenge.ChallengeId);
        var challengeJson = JsonSerializer.Serialize(challengeResult);
        Assert.That(challengeJson, Does.Contain("valid"));

        // 4. Finalize (submit CSR)
        using var csrKey = RSA.Create(2048);
        var csrRequest = new CertificateRequest(
            "CN=test.example.com",
            csrKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName("test.example.com");
        csrRequest.CertificateExtensions.Add(sanBuilder.Build());
        byte[] csrBytes = csrRequest.CreateSigningRequest();
        var csrB64 = AcmeJwsHandler.Base64UrlEncode(csrBytes);
        var csrPayload = $$"""{"csr":"{{csrB64}}"}""";
        var nonce3 = await _acmeService.CreateNonceAsync();
        var body3 = JwsBuilder.BuildJws(_accountKey, _finalizeUrl, csrPayload, nonce3, kid: kid);
        var finalizeOrder = await _acmeService.FinalizeOrderAsync(StreamFrom(body3), _orderId, _finalizeUrl);
        var finalizeJson = JsonSerializer.Serialize(finalizeOrder);
        Assert.That(finalizeJson, Does.Contain("valid"));
        Assert.That(finalizeJson, Does.Contain("certificate"));

        // 5. Get certificate
        var certPem = await _acmeService.GetCertificateAsync(_orderId, _accountId);
        Assert.That(certPem, Is.Not.Null.And.Not.Empty);
        var pemStr = Encoding.UTF8.GetString(certPem!);
        Assert.That(pemStr, Does.Contain("-----BEGIN CERTIFICATE-----"));
        Assert.That(pemStr, Does.Contain("-----END CERTIFICATE-----"));
    }

    [Test]
    public async Task FullFlow_GetOrder_AfterFinalize_ReturnsValidStatusAndCertificateUrl()
    {
        await FullFlow_NewAccount_NewOrder_ValidateChallenge_Finalize_GetCertificate();

        var order = await _acmeService.GetOrderAsync(_orderId, _accountId);
        var json = JsonSerializer.Serialize(order);
        Assert.That(json, Does.Contain("valid"));
        Assert.That(json, Does.Contain("certificate"));
    }

    private static Stream StreamFrom(string s)
    {
        var ms = new MemoryStream(Encoding.UTF8.GetBytes(s));
        ms.Position = 0;
        return ms;
    }
}

internal sealed class MockHttpClientFactory : IHttpClientFactory
{
    private readonly HttpClient _client;

    public MockHttpClientFactory(HttpClient client) => _client = client;

    public HttpClient CreateClient(string name) => _client;
}
