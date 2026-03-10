using CertA.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CertA.Controllers.Api;

[Route("api/ca")]
[ApiController]
[Authorize]
public class CaApiController : ControllerBase
{
    private readonly ICertificateAuthorityService _caService;

    public CaApiController(ICertificateAuthorityService caService)
    {
        _caService = caService;
    }

    [HttpGet]
    public async Task<IActionResult> Get()
    {
        var ca = await _caService.GetActiveCAAsync();
        if (ca == null) return Ok((object?)null);
        return Ok(new
        {
            id = ca.Id,
            name = ca.Name,
            commonName = ca.CommonName,
            organization = ca.Organization,
            country = ca.Country,
            state = ca.State,
            locality = ca.Locality,
            createdDate = ca.CreatedDate,
            expiryDate = ca.ExpiryDate,
            isActive = ca.IsActive
        });
    }
}
