using CertA.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace CertA.Controllers.Api;

[Route("api/dashboard")]
[ApiController]
[Authorize]
public class DashboardApiController : ControllerBase
{
    private readonly ICertificateService _certificateService;
    private readonly ICertificateAuthorityService _caService;

    public DashboardApiController(
        ICertificateService certificateService,
        ICertificateAuthorityService caService)
    {
        _certificateService = certificateService;
        _caService = caService;
    }

    [HttpGet]
    public async Task<IActionResult> Get()
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrEmpty(userId)) return Unauthorized();

        var totalCertificates = 0;
        var recentCertificates = new List<object>();
        var activeCA = false;

        try
        {
            var certificates = await _certificateService.ListAsync(userId);
            totalCertificates = certificates.Count;
            foreach (var c in certificates.Take(5))
            {
                recentCertificates.Add(new
                {
                    id = c.Id,
                    commonName = c.CommonName,
                    type = c.Type.ToString(),
                    status = (int)c.Status
                });
            }
            var ca = await _caService.GetActiveCAAsync();
            activeCA = ca != null;
        }
        catch { /* ignore */ }

        return Ok(new
        {
            totalCertificates,
            activeCA,
            recentCertificates
        });
    }
}
