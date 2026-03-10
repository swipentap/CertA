using System.Collections.Immutable;
using System.Security.Claims;
using CertA.Models;
using CertA.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace CertA.Controllers;

/// <summary>OpenIddict authorization and token endpoints. Used when OAuth2 UseEmbedded is true.</summary>
public sealed class ConnectController : Controller
{
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly IUserService _userService;
    private readonly ILogger<ConnectController> _logger;

    public ConnectController(
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictScopeManager scopeManager,
        IUserService userService,
        ILogger<ConnectController> logger)
    {
        _applicationManager = applicationManager;
        _scopeManager = scopeManager;
        _userService = userService;
        _logger = logger;
    }

    [HttpGet("~/connect/authorize")]
    [HttpPost("~/connect/authorize")]
    [AllowAnonymous]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> Authorize(CancellationToken ct)
    {
        var request = HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        if (User.Identity?.IsAuthenticated != true)
        {
            var returnUrl = Request.Path + Request.QueryString;
            return Redirect($"/login?returnUrl={Uri.EscapeDataString(Uri.EscapeDataString(returnUrl))}");
        }

        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        var user = userId != null ? await _userService.GetUserByIdAsync(userId) : null;
        if (user == null || !user.IsActive)
        {
            return Challenge(CookieAuthenticationDefaults.AuthenticationScheme);
        }

        var roles = await _userService.GetUserRolesAsync(user.Id);
        var hasAdmin = roles.Any(r => string.Equals(r, "Admin", StringComparison.OrdinalIgnoreCase));
        _logger.LogInformation("ConnectController.Authorize: user={Email} roles=[{Roles}] hasAdmin={HasAdmin}", user.Email, string.Join(",", roles), hasAdmin);
        if (!hasAdmin)
        {
            _logger.LogWarning("User {Email} rejected at authorization: Admin role required.", user.Email);
            return Redirect("/access-denied?message=" + Uri.EscapeDataString("Admin role required."));
        }

        var application = await _applicationManager.FindByClientIdAsync(request.ClientId!, ct)
            ?? throw new InvalidOperationException("The application cannot be found.");

        var identity = new ClaimsIdentity(
            authenticationType: "OpenIddict",
            nameType: Claims.Name,
            roleType: Claims.Role);

        identity.SetClaim(Claims.Subject, user.Id);
        identity.SetClaim(Claims.Email, user.Email);
        identity.SetClaim(Claims.Name, user.UserName ?? user.Email ?? "");
        identity.SetClaims(Claims.Role, ImmutableArray.CreateRange(roles));

        identity.SetDestinations(claim => claim.Type switch
        {
            Claims.Name or Claims.Email or Claims.Role
                => [Destinations.AccessToken, Destinations.IdentityToken],
            _ => [Destinations.AccessToken]
        });

        var principal = new ClaimsPrincipal(identity);
        principal.SetScopes(request.GetScopes());
        var resources = new List<string>();
        await foreach (var r in _scopeManager.ListResourcesAsync(principal.GetScopes(), ct))
            resources.Add(r);
        principal.SetResources(resources);

        return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    [HttpPost("~/connect/token")]
    [IgnoreAntiforgeryToken]
    [Produces("application/json")]
    public async Task<IActionResult> Exchange(CancellationToken ct)
    {
        var request = HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        if (request.IsAuthorizationCodeGrantType())
        {
            var principal = (await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal
                ?? throw new InvalidOperationException("The token cannot be retrieved.");

            return SignIn(principal!, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        if (request.IsRefreshTokenGrantType())
        {
            var principal = (await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal
                ?? throw new InvalidOperationException("The refresh token cannot be retrieved.");

            return SignIn(principal!, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        throw new InvalidOperationException("The specified grant type is not supported.");
    }
}
