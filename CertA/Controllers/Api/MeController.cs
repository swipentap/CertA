using CertA.Options;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System.Security.Claims;

namespace CertA.Controllers.Api;

[Route("api/[controller]")]
[ApiController]
public class MeController : ControllerBase
{
    private readonly IOptions<OAuth2Options> _oauth2Options;

    public MeController(IOptions<OAuth2Options> oauth2Options)
    {
        _oauth2Options = oauth2Options;
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult Get()
    {
        if (User.Identity?.IsAuthenticated != true)
        {
            return Ok(new
            {
                user = (object?)null,
                oauth2Enabled = _oauth2Options.Value.Enabled,
                oauth2UseEmbedded = _oauth2Options.Value.UseEmbedded
            });
        }
        var name = User.FindFirstValue(ClaimTypes.Name) ?? User.FindFirstValue(ClaimTypes.Email) ?? "Account";
        var email = User.FindFirstValue(ClaimTypes.Email) ?? User.Identity.Name;
        return Ok(new
        {
            user = new { name, email },
            oauth2Enabled = _oauth2Options.Value.Enabled,
            oauth2UseEmbedded = _oauth2Options.Value.UseEmbedded
        });
    }
}
