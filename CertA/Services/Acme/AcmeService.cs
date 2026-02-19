using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using CertA.Models;
using CertA.Options;
using CertA.Services;

namespace CertA.Services.Acme;

public interface IAcmeService
{
    Task<object> GetDirectoryAsync(string baseUrl);
    Task<string> CreateNonceAsync();
    Task<(object Account, string? Location)> NewAccountAsync(Stream body, string url);
    Task<object> NewOrderAsync(Stream body, string url);
    Task<object> GetOrderAsync(string orderId, string accountId);
    Task<object> GetAuthorizationAsync(string authId);
    Task<object> HandleChallengeAsync(string challengeId);
    Task<object> FinalizeOrderAsync(Stream body, string orderId, string url);
    Task<byte[]?> GetCertificateAsync(string orderId, string accountId);
    Task<AcmeJwsPayload?> ParseJwsForAccountAsync(Stream body, string url);
}

public class AcmeService : IAcmeService
{
    private readonly IAcmeStorageService _storage;
    private readonly ICertificateAuthorityService _caService;
    private readonly IAcmeCertificatePersistence _certPersistence;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly AcmeOptions _options;
    private readonly IUserService _userService;
    private readonly ILogger<AcmeService> _logger;

    public AcmeService(
        IAcmeStorageService storage,
        ICertificateAuthorityService caService,
        IAcmeCertificatePersistence certPersistence,
        IHttpClientFactory httpClientFactory,
        Microsoft.Extensions.Options.IOptions<AcmeOptions> options,
        IUserService userService,
        ILogger<AcmeService> logger)
    {
        _storage = storage;
        _caService = caService;
        _certPersistence = certPersistence;
        _httpClientFactory = httpClientFactory;
        _options = options.Value;
        _userService = userService;
        _logger = logger;
    }

    public async Task<object> GetDirectoryAsync(string baseUrl)
    {
        var acmeDir = baseUrl.TrimEnd('/') + "/acme";
        return new
        {
            newNonce = acmeDir + "/newNonce",
            newAccount = acmeDir + "/newAccount",
            newOrder = acmeDir + "/newOrder",
            revokeCert = acmeDir + "/revokeCert",
            keyChange = acmeDir + "/keyChange"
        };
    }

    public async Task<string> CreateNonceAsync()
    {
        return await _storage.CreateNonceAsync(TimeSpan.FromMinutes(5));
    }

    public async Task<(object Account, string? Location)> NewAccountAsync(Stream body, string url)
    {
        var payload = await ParseJwsAsync(body, url, null);
        var payloadJson = payload.PayloadJson;
        var onlyReturnExisting = payloadJson == null || payloadJson == "{}";

        string? jwkJson = null;
        if (!string.IsNullOrEmpty(payload.ProtectedHeaderJson))
        {
            using var headerDoc = JsonDocument.Parse(payload.ProtectedHeaderJson);
            if (headerDoc.RootElement.TryGetProperty("jwk", out var jwkEl))
                jwkJson = jwkEl.GetRawText();
        }

        if (string.IsNullOrEmpty(jwkJson))
            throw new AcmeException("newAccount requires jwk in protected header", "malformed");

        var thumbprint = AcmeJwsHandler.Base64UrlEncode(AcmeJwsHandler.ComputeJwkThumbprint(jwkJson));
        var existing = await _storage.GetAccountByThumbprintAsync(thumbprint);

        if (existing != null)
        {
            if (onlyReturnExisting)
                return (AccountResponse(existing), null);
            throw new AcmeException("account exists", "accountDoesNotExist");
        }

        var accountId = "acct_" + Guid.NewGuid().ToString("N")[..16];
        var account = await _storage.CreateAccountAsync(accountId, jwkJson, thumbprint);
        var location = _options.DirectoryBaseUrl.TrimEnd('/') + "/acme/acct/" + accountId;
        return (AccountResponse(account), location);
    }

    public async Task<object> NewOrderAsync(Stream body, string url)
    {
        var payload = await ParseJwsAsync(body, url, null);
        var accountId = payload.AccountId ?? throw new AcmeException("account required", "unauthorized");
        if (string.IsNullOrEmpty(payload.PayloadJson))
            throw new AcmeException("newOrder requires payload", "malformed");

        using var doc = JsonDocument.Parse(payload.PayloadJson!);
        var root = doc.RootElement;
        if (!root.TryGetProperty("identifiers", out var idsEl))
            throw new AcmeException("identifiers required", "malformed");

        var identifiers = new List<object>();
        foreach (var id in idsEl.EnumerateArray())
        {
            var type = id.TryGetProperty("type", out var t) ? t.GetString() : "dns";
            var value = id.TryGetProperty("value", out var v) ? v.GetString() : "";
            if (string.IsNullOrEmpty(value))
                throw new AcmeException("identifier value required", "malformed");
            identifiers.Add(new { type, value });
        }

        if (identifiers.Count == 0)
            throw new AcmeException("at least one identifier required", "malformed");

        var orderId = "order_" + Guid.NewGuid().ToString("N")[..16];
        var expires = DateTime.UtcNow.AddDays(1);
        var identifiersJson = JsonSerializer.Serialize(identifiers);
        await _storage.CreateOrderAsync(orderId, accountId, identifiersJson, expires);

        var acct = await _storage.GetAccountByKeyIdAsync(accountId);
        if (acct == null) throw new AcmeException("account not found", "unauthorized");
        var tp = AcmeJwsHandler.Base64UrlEncode(AcmeJwsHandler.ComputeJwkThumbprint(acct.KeyJwk));

        var authIds = new List<string>();
        foreach (var id in idsEl.EnumerateArray())
        {
            var type = id.TryGetProperty("type", out var tEl) ? tEl.GetString() ?? "dns" : "dns";
            var value = id.TryGetProperty("value", out var vEl) ? vEl.GetString() ?? "" : "";
            var authId = "authz_" + Guid.NewGuid().ToString("N")[..16];
            await _storage.CreateAuthorizationAsync(authId, orderId, type, value, expires);

            var token = Guid.NewGuid().ToString("N");
            var keyAuth = token + "." + tp;

            var challengeId = "chall_" + Guid.NewGuid().ToString("N")[..16];
            await _storage.CreateChallengeAsync(challengeId, authId, "http-01", token, keyAuth);
            authIds.Add(_options.DirectoryBaseUrl.TrimEnd('/') + "/acme/authz/" + authId);
        }

        var order = await _storage.GetOrderAsync(orderId);
        return new
        {
            status = order!.Status,
            expires = order.Expires.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            identifiers = JsonSerializer.Deserialize<object[]>(identifiersJson),
            authorizations = authIds,
            finalize = _options.DirectoryBaseUrl.TrimEnd('/') + "/acme/order/" + orderId + "/finalize",
            certificate = (string?)null
        };
    }

    public async Task<object> GetOrderAsync(string orderId, string accountId)
    {
        var order = await _storage.GetOrderAsync(orderId);
        if (order == null || order.AccountId != accountId)
            throw new AcmeException("order not found", "unauthorized");

        var auths = await _storage.GetAuthorizationsForOrderAsync(orderId);
        var authUrls = auths.Select(a => _options.DirectoryBaseUrl.TrimEnd('/') + "/acme/authz/" + a.AuthId).ToList();

        var ids = JsonSerializer.Deserialize<JsonElement[]>(order.Identifiers) ?? Array.Empty<JsonElement>();
        var identifiers = ids.Select(e => new { type = e.GetProperty("type").GetString(), value = e.GetProperty("value").GetString() }).ToArray();

        return new
        {
            status = order.Status,
            expires = order.Expires.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            identifiers,
            authorizations = authUrls,
            finalize = _options.DirectoryBaseUrl.TrimEnd('/') + "/acme/order/" + orderId + "/finalize",
            certificate = order.Status == "valid" ? _options.DirectoryBaseUrl.TrimEnd('/') + "/acme/order/" + orderId + "/certificate" : (string?)null
        };
    }

    public async Task<object> GetAuthorizationAsync(string authId)
    {
        var auth = await _storage.GetAuthorizationAsync(authId);
        if (auth == null)
            throw new AcmeException("authorization not found", "unauthorized");

        var challenges = await _storage.GetChallengesForAuthAsync(authId);
        var challengeObjs = challenges.Select(c => new
        {
            type = c.Type,
            url = _options.DirectoryBaseUrl.TrimEnd('/') + "/acme/chall/" + c.ChallengeId,
            token = c.Token,
            status = c.Status
        }).ToArray();

        return new
        {
            status = auth.Status,
            expires = auth.Expires.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            identifier = new { type = auth.IdentifierType, value = auth.IdentifierValue },
            challenges = challengeObjs
        };
    }

    public async Task<object> HandleChallengeAsync(string challengeId)
    {
        var challenge = await _storage.GetChallengeAsync(challengeId);
        if (challenge == null)
            throw new AcmeException("challenge not found", "unauthorized");
        if (challenge.Type != "http-01")
            throw new AcmeException("only http-01 supported", "badChallenge");

        if (challenge.Status == "valid")
            return new { type = challenge.Type, url = "", token = challenge.Token, status = "valid" };

        var auth = await _storage.GetAuthorizationAsync(challenge.AuthId);
        if (auth == null)
            throw new AcmeException("authorization not found", "unauthorized");

        await _storage.UpdateChallengeStatusAsync(challengeId, "processing");

        var uri = new Uri("http://" + auth.IdentifierValue + "/.well-known/acme-challenge/" + challenge.Token);
        try
        {
            using var client = _httpClientFactory.CreateClient();
            client.Timeout = TimeSpan.FromSeconds(_options.HttpChallengeTimeoutSeconds);
            var resp = await client.GetStringAsync(uri);
            var expected = challenge.KeyAuthorization.Trim();
            var actual = resp.Trim();
            if (string.Equals(expected, actual, StringComparison.Ordinal))
            {
                await _storage.UpdateChallengeStatusAsync(challengeId, "valid", DateTime.UtcNow);
                await _storage.UpdateAuthorizationStatusAsync(challenge.AuthId, "valid");
                _logger.LogInformation("HTTP-01 challenge validated for {Identifier}", auth.IdentifierValue);
            }
            else
            {
                await _storage.UpdateChallengeStatusAsync(challengeId, "invalid");
                await _storage.UpdateAuthorizationStatusAsync(challenge.AuthId, "invalid");
                throw new AcmeException("validation failed: response mismatch", "unauthorized");
            }
        }
        catch (Exception ex)
        {
            await _storage.UpdateChallengeStatusAsync(challengeId, "invalid");
            await _storage.UpdateAuthorizationStatusAsync(challenge.AuthId, "invalid");
            _logger.LogWarning(ex, "HTTP-01 validation failed for {Identifier}", auth.IdentifierValue);
            throw new AcmeException("validation failed: " + ex.Message, "unauthorized");
        }

        return new { type = challenge.Type, url = "", token = challenge.Token, status = "valid" };
    }

    public async Task<object> FinalizeOrderAsync(Stream body, string orderId, string url)
    {
        var payload = await ParseJwsAsync(body, url, null);
        var accountId = payload.AccountId ?? throw new AcmeException("account required", "unauthorized");
        if (string.IsNullOrEmpty(payload.PayloadJson))
            throw new AcmeException("finalize requires payload", "malformed");

        using var doc = JsonDocument.Parse(payload.PayloadJson!);
        var root = doc.RootElement;
        if (!root.TryGetProperty("csr", out var csrB64))
            throw new AcmeException("csr required", "malformed");

        var order = await _storage.GetOrderAsync(orderId);
        if (order == null || order.AccountId != accountId)
            throw new AcmeException("order not found", "unauthorized");
        if (order.Status == "valid")
            return await GetOrderAsync(orderId, accountId);

        var auths = await _storage.GetAuthorizationsForOrderAsync(orderId);
        var allValid = auths.All(a => a.Status == "valid");
        if (!allValid)
            throw new AcmeException("not all authorizations valid", "orderNotReady");

        var csrBytes = AcmeJwsHandler.Base64UrlDecode(csrB64.GetString()!);

        CertificateRequest request;
        try
        {
            request = CertificateRequest.LoadSigningRequest(csrBytes, HashAlgorithmName.SHA256, CertificateRequestLoadOptions.Default, RSASignaturePadding.Pkcs1);
        }
        catch (Exception ex)
        {
            throw new AcmeException("invalid CSR: " + ex.Message, "badCsr");
        }

        var cn = request.SubjectName?.Decode(X500DistinguishedNameFlags.None).Split(',').FirstOrDefault(s => s.TrimStart().StartsWith("CN="))?.TrimStart().Substring(3) ?? "acme";
        var sans = new List<string>();
        foreach (var ext in request.CertificateExtensions)
        {
            if (ext is X509SubjectAlternativeNameExtension sanExt)
            {
                var sanStr = sanExt.Format(false);
                foreach (var part in sanStr.Split(','))
                {
                    var p = part.Trim();
                    if (p.StartsWith("DNS Name="))
                        sans.Add(p.Substring(9));
                }
            }
        }
        var sansStr = sans.Count > 0 ? string.Join(",", sans) : null;

        var signedCert = await _caService.SignCertificateAsync(request, cn, sansStr, CertificateType.Server);
        var certPem = signedCert.ExportCertificatePem();

        var userId = await ResolveSystemUserIdAsync();
        var notBefore = DateTime.UtcNow;
        var notAfter = notBefore.AddYears(1);
        var serialNumber = Guid.NewGuid().ToString("N")[..16];

        var rsaPub = signedCert.GetRSAPublicKey();
        var publicKeyPem = rsaPub != null ? rsaPub.ExportRSAPublicKeyPem() : "";

        var certId = await _certPersistence.SaveAcmeCertificateAsync(
            cn,
            sansStr,
            serialNumber,
            notBefore,
            notAfter,
            certPem,
            publicKeyPem,
            userId);

        await _storage.UpdateOrderStatusAsync(orderId, "valid", certPem, certId);

        return await GetOrderAsync(orderId, accountId);
    }

    public async Task<byte[]?> GetCertificateAsync(string orderId, string accountId)
    {
        var order = await _storage.GetOrderAsync(orderId);
        if (order == null || order.AccountId != accountId || order.Status != "valid" || string.IsNullOrEmpty(order.CertificatePem))
            return null;
        return Encoding.UTF8.GetBytes(order.CertificatePem);
    }

    private async Task<string> ResolveSystemUserIdAsync()
    {
        if (!string.IsNullOrEmpty(_options.SystemUserId))
            return _options.SystemUserId;
        var admin = await _userService.GetUserByEmailAsync("admin@certa.local");
        if (admin != null)
            return admin.Id;
        throw new InvalidOperationException("Acme:SystemUserId not configured and no admin user found");
    }

    private static object AccountResponse(Models.Acme.AcmeAccount a)
    {
        return new
        {
            status = a.Status,
            contact = Array.Empty<string>(),
            termsOfServiceAgreed = (bool?)null,
            orders = (string?)null
        };
    }

    public async Task<AcmeJwsPayload?> ParseJwsForAccountAsync(Stream body, string url)
    {
        try
        {
            return await ParseJwsAsync(body, url, null);
        }
        catch
        {
            return null;
        }
    }

    private async Task<AcmeJwsPayload> ParseJwsAsync(Stream body, string url, string? _)
    {
        async Task<(RSA? Key, string? AccountId)> GetKey(string kid, string __)
        {
            var id = kid.Split('/').LastOrDefault() ?? kid;
            if (!string.IsNullOrEmpty(id) && (id.StartsWith("acct_") || (id.Length > 0 && char.IsLetterOrDigit(id[0]))))
            {
                var acct = await _storage.GetAccountByKeyIdAsync(id);
                if (acct != null)
                    return (AcmeJwsHandler.JwkToRsa(acct.KeyJwk), acct.AccountId);
            }
            return (null, null);
        }

        return await AcmeJwsHandler.ParseAndVerifyAsync(body, url, GetKey, _storage.ConsumeNonceAsync);
    }
}
