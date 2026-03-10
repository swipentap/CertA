using CertA.Options;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace CertA.Controllers.Api;

[Route("api/auth")]
[ApiController]
[IgnoreAntiforgeryToken]
public class AuthApiController : ControllerBase
{
    private readonly IOptions<OAuth2Options> _oauth2Options;

    public AuthApiController(IOptions<OAuth2Options> oauth2Options)
    {
        _oauth2Options = oauth2Options;
    }

    /// <summary>
    /// Starts OAuth2/OIDC redirect flow (Keycloak). Use when oauth2Enabled and !oauth2UseEmbedded.
    /// SPA calls this instead of server-side /Account/Login.
    /// </summary>
    [HttpGet("authorize")]
    [AllowAnonymous]
    public IActionResult Authorize([FromQuery] string? returnUrl = null)
    {
        var opts = _oauth2Options.Value;
        if (!opts.Enabled || opts.UseEmbedded)
        {
            var q = "?form=1";
            if (!string.IsNullOrEmpty(returnUrl) && returnUrl.Length < 500)
                q += "&returnUrl=" + Uri.EscapeDataString(returnUrl);
            return Redirect("/login" + q);
        }
        var dest = !string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl) ? returnUrl : "/";
        var completeUrl = "/Account/SignInComplete?returnUrl=" + Uri.EscapeDataString(dest);
        return Challenge(new AuthenticationProperties { RedirectUri = completeUrl }, OpenIdConnectDefaults.AuthenticationScheme);
    }
}
