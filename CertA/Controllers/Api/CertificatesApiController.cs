using CertA.Models;
using CertA.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace CertA.Controllers.Api;

[Route("api/certificates")]
[ApiController]
[Authorize]
[IgnoreAntiforgeryToken]
public class CertificatesApiController : ControllerBase
{
    private readonly ICertificateService _service;
    private readonly ILogger<CertificatesApiController> _logger;

    public CertificatesApiController(ICertificateService service, ILogger<CertificatesApiController> logger)
    {
        _service = service;
        _logger = logger;
    }

    [HttpGet]
    public async Task<IActionResult> List()
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrEmpty(userId)) return Unauthorized();
        try
        {
            var list = await _service.ListAsync(userId);
            var result = list.Select(c => new
            {
                id = c.Id,
                commonName = c.CommonName,
                subjectAlternativeNames = c.SubjectAlternativeNames,
                serialNumber = c.SerialNumber,
                issuedDate = c.IssuedDate,
                expiryDate = c.ExpiryDate,
                status = (int)c.Status,
                type = (int)c.Type
            }).ToList();
            return Ok(result);
        }
        catch
        {
            return Ok(new List<object>());
        }
    }

    [HttpGet("{id:int}")]
    public async Task<IActionResult> Get(int id)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrEmpty(userId)) return Unauthorized();
        var cert = await _service.GetAsync(id, userId);
        if (cert == null) return NotFound();
        string haproxyContent = "";
        try
        {
            var bytes = await _service.GetHAProxyFormatAsync(id, userId);
            haproxyContent = System.Text.Encoding.UTF8.GetString(bytes);
        }
        catch { /* ignore */ }
        return Ok(new
        {
            certificate = new
            {
                id = cert.Id,
                commonName = cert.CommonName,
                subjectAlternativeNames = cert.SubjectAlternativeNames,
                serialNumber = cert.SerialNumber,
                issuedDate = cert.IssuedDate,
                expiryDate = cert.ExpiryDate,
                status = (int)cert.Status,
                type = (int)cert.Type,
                certificatePem = cert.CertificatePem,
                publicKeyPem = cert.PublicKeyPem,
                privateKeyPem = cert.PrivateKeyPem
            },
            haproxyContent
        });
    }

    [HttpPost]
    public async Task<IActionResult> Create([FromBody] CreateCertificateApiRequest model)
    {
        if (model == null || string.IsNullOrWhiteSpace(model.CommonName))
            return BadRequest(new { message = "CommonName is required." });
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrEmpty(userId)) return Unauthorized();
        try
        {
            var type = model.Type is >= 0 and <= 4 ? (CertificateType)model.Type : CertificateType.Server;
            var created = await _service.CreateAsync(model.CommonName.Trim(), model.SubjectAlternativeNames?.Trim(), type, userId);
            _logger.LogInformation("Created certificate {Id} for {CommonName} via API", created.Id, created.CommonName);
            return Ok(new { id = created.Id });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to create certificate via API");
            return BadRequest(new { message = ex.Message });
        }
    }

    [HttpDelete("{id:int}")]
    public async Task<IActionResult> Delete(int id)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrEmpty(userId)) return Unauthorized();
        var success = await _service.DeleteAsync(id, userId);
        if (!success) return NotFound();
        return Ok(new { success = true });
    }
}

public class CreateCertificateApiRequest
{
    public string CommonName { get; set; } = "";
    public string? SubjectAlternativeNames { get; set; }
    public int Type { get; set; }
}
