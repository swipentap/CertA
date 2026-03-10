using CertA.Models;
using CertA.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using AuthService = CertA.Services.IAuthenticationService;

namespace CertA.Controllers.Api;

[Route("api/account")]
[ApiController]
[IgnoreAntiforgeryToken]
public class AccountApiController : ControllerBase
{
    private readonly IUserService _userService;
    private readonly AuthService _authService;
    private readonly ILogger<AccountApiController> _logger;

    public AccountApiController(
        IUserService userService,
        AuthService authService,
        ILogger<AccountApiController> logger)
    {
        _userService = userService;
        _authService = authService;
        _logger = logger;
    }

    [HttpPost("register")]
    [AllowAnonymous]
    public async Task<IActionResult> Register([FromBody] RegisterApiRequest model)
    {
        if (model == null || string.IsNullOrEmpty(model.Email) || string.IsNullOrEmpty(model.Password))
            return BadRequest(new { message = "Email and password are required." });
        if (model.Password != model.ConfirmPassword)
            return BadRequest(new { message = "Passwords do not match." });
        if (model.Password.Length < 6)
            return BadRequest(new { message = "Password must be at least 6 characters." });

        var user = new ApplicationUser
        {
            UserName = model.Email,
            Email = model.Email,
            FirstName = model.FirstName ?? "",
            LastName = model.LastName ?? "",
            Organization = model.Organization
        };

        var created = await _userService.CreateUserAsync(user, model.Password);
        if (!created)
            return BadRequest(new { message = "Failed to create account. Email may already be in use." });

        _logger.LogInformation("User created account via API: {Email}", model.Email);
        var principal = await _authService.CreateClaimsPrincipalAsync(user);
        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);
        return Ok(new { success = true });
    }

    [HttpGet("profile")]
    [Authorize]
    public async Task<IActionResult> GetProfile()
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrEmpty(userId)) return Unauthorized();
        var user = await _userService.GetUserByIdAsync(userId);
        if (user == null) return Unauthorized();
        return Ok(new
        {
            firstName = user.FirstName ?? "",
            lastName = user.LastName ?? "",
            email = user.Email ?? "",
            organization = user.Organization,
            createdDate = user.CreatedDate,
            isActive = user.IsActive
        });
    }

    [HttpPut("profile")]
    [Authorize]
    public async Task<IActionResult> UpdateProfile([FromBody] ProfileApiRequest model)
    {
        if (model == null) return BadRequest();
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrEmpty(userId)) return Unauthorized();
        var user = await _userService.GetUserByIdAsync(userId);
        if (user == null) return Unauthorized();

        user.FirstName = model.FirstName ?? "";
        user.LastName = model.LastName ?? "";
        user.Organization = model.Organization;
        var updated = await _userService.UpdateUserAsync(user);
        if (!updated) return BadRequest(new { message = "Failed to update profile." });
        return Ok(new { success = true });
    }
}

public class RegisterApiRequest
{
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    [Required] public string Email { get; set; } = "";
    public string? Organization { get; set; }
    [Required] [MinLength(6)] public string Password { get; set; } = "";
    public string? ConfirmPassword { get; set; }
}

public class ProfileApiRequest
{
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public string? Organization { get; set; }
}
