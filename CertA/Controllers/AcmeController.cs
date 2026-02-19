using CertA.Services.Acme;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace CertA.Controllers;

[Route("acme")]
[ApiController]
[AllowAnonymous]
public class AcmeController : ControllerBase
{
    private readonly IAcmeService _acmeService;
    private readonly IOptions<CertA.Options.AcmeOptions> _options;
    private readonly ILogger<AcmeController> _logger;

    public AcmeController(IAcmeService acmeService, IOptions<CertA.Options.AcmeOptions> options, ILogger<AcmeController> logger)
    {
        _acmeService = acmeService;
        _options = options;
        _logger = logger;
    }

    [HttpGet("directory")]
    public async Task<IActionResult> Directory()
    {
        if (!_options.Value.Enabled)
            return NotFound();

        var baseUrl = GetBaseUrl();
        var dir = await _acmeService.GetDirectoryAsync(baseUrl);
        return AcmeJson(dir);
    }

    [HttpGet("newNonce")]
    public async Task<IActionResult> NewNonce()
    {
        if (!_options.Value.Enabled)
            return NotFound();

        var nonce = await _acmeService.CreateNonceAsync();
        Response.Headers["Replay-Nonce"] = nonce;
        return NoContent();
    }

    [HttpPost("newAccount")]
    public async Task<IActionResult> NewAccount()
    {
        if (!_options.Value.Enabled)
            return NotFound();

        var url = GetBaseUrl() + "/acme/newAccount";
        try
        {
            Request.EnableBuffering();
            var (account, location) = await _acmeService.NewAccountAsync(Request.Body, url);
            var nonce = await _acmeService.CreateNonceAsync();
            Response.Headers["Replay-Nonce"] = nonce;
            if (!string.IsNullOrEmpty(location))
                Response.Headers["Location"] = location;
            return AcmeJson(account, 201);
        }
        catch (AcmeException ex)
        {
            return AcmeError(ex);
        }
    }

    [HttpPost("newOrder")]
    public async Task<IActionResult> NewOrder()
    {
        if (!_options.Value.Enabled)
            return NotFound();

        var url = GetBaseUrl() + "/acme/newOrder";
        try
        {
            Request.EnableBuffering();
            var order = await _acmeService.NewOrderAsync(Request.Body, url);
            var nonce = await _acmeService.CreateNonceAsync();
            Response.Headers["Replay-Nonce"] = nonce;
            return AcmeJson(order, 201);
        }
        catch (AcmeException ex)
        {
            return AcmeError(ex);
        }
    }

    [HttpPost("order/{orderId}")]
    public async Task<IActionResult> GetOrder(string orderId)
    {
        if (!_options.Value.Enabled)
            return NotFound();

        var url = GetBaseUrl() + "/acme/order/" + orderId;
        try
        {
            Request.EnableBuffering();
            var accountId = await GetAccountIdFromJwsAsync(url);
            if (string.IsNullOrEmpty(accountId))
                return AcmeError(new AcmeException("account required", "unauthorized"), 401);

            var order = await _acmeService.GetOrderAsync(orderId, accountId);
            var nonce = await _acmeService.CreateNonceAsync();
            Response.Headers["Replay-Nonce"] = nonce;
            return AcmeJson(order);
        }
        catch (AcmeException ex)
        {
            return AcmeError(ex);
        }
    }

    [HttpPost("order/{orderId}/finalize")]
    public async Task<IActionResult> FinalizeOrder(string orderId)
    {
        if (!_options.Value.Enabled)
            return NotFound();

        var url = GetBaseUrl() + "/acme/order/" + orderId + "/finalize";
        try
        {
            Request.EnableBuffering();
            var order = await _acmeService.FinalizeOrderAsync(Request.Body, orderId, url);
            var nonce = await _acmeService.CreateNonceAsync();
            Response.Headers["Replay-Nonce"] = nonce;
            return AcmeJson(order);
        }
        catch (AcmeException ex)
        {
            return AcmeError(ex);
        }
    }

    [HttpPost("order/{orderId}/certificate")]
    public async Task<IActionResult> GetCertificate(string orderId)
    {
        if (!_options.Value.Enabled)
            return NotFound();

        var url = GetBaseUrl() + "/acme/order/" + orderId + "/certificate";
        try
        {
            Request.EnableBuffering();
            var accountId = await GetAccountIdFromJwsAsync(url);
            if (string.IsNullOrEmpty(accountId))
                return AcmeError(new AcmeException("account required", "unauthorized"), 401);

            var cert = await _acmeService.GetCertificateAsync(orderId, accountId);
            if (cert == null)
                return NotFound();
            return File(cert, "application/pem-certificate-chain");
        }
        catch (AcmeException ex)
        {
            return AcmeError(ex);
        }
    }

    [HttpGet("authz/{authId}")]
    public async Task<IActionResult> GetAuthorization(string authId)
    {
        if (!_options.Value.Enabled)
            return NotFound();

        try
        {
            var auth = await _acmeService.GetAuthorizationAsync(authId);
            var nonce = await _acmeService.CreateNonceAsync();
            Response.Headers["Replay-Nonce"] = nonce;
            return AcmeJson(auth);
        }
        catch (AcmeException ex)
        {
            return AcmeError(ex);
        }
    }

    [HttpPost("chall/{challengeId}")]
    public async Task<IActionResult> HandleChallenge(string challengeId)
    {
        if (!_options.Value.Enabled)
            return NotFound();

        var url = GetBaseUrl() + "/acme/chall/" + challengeId;
        try
        {
            Request.EnableBuffering();
            _ = await _acmeService.ParseJwsForAccountAsync(Request.Body, url);
            var challenge = await _acmeService.HandleChallengeAsync(challengeId);
            var nonce = await _acmeService.CreateNonceAsync();
            Response.Headers["Replay-Nonce"] = nonce;
            return AcmeJson(challenge);
        }
        catch (AcmeException ex)
        {
            return AcmeError(ex);
        }
    }

    private string GetBaseUrl()
    {
        var baseUrl = _options.Value.DirectoryBaseUrl;
        if (!string.IsNullOrEmpty(baseUrl))
            return baseUrl.TrimEnd('/');

        var scheme = Request.Scheme;
        var host = Request.Host.Value;
        return $"{scheme}://{host}";
    }

    private async Task<string?> GetAccountIdFromJwsAsync(string url)
    {
        if (Request.ContentLength == 0 || Request.ContentLength == null)
            return null;
        var payload = await _acmeService.ParseJwsForAccountAsync(Request.Body, url);
        return payload?.AccountId;
    }

    private IActionResult AcmeJson(object value, int statusCode = 200)
    {
        return new JsonResult(value, new System.Text.Json.JsonSerializerOptions
        {
            PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
        })
        {
            StatusCode = statusCode,
            ContentType = "application/json"
        };
    }

    private IActionResult AcmeError(AcmeException ex, int statusCode = 400)
    {
        var nonce = _acmeService.CreateNonceAsync().GetAwaiter().GetResult();
        Response.Headers["Replay-Nonce"] = nonce;
        return AcmeJson(new { type = "urn:ietf:params:acme:error:" + ex.Type, detail = ex.Message }, statusCode);
    }
}
