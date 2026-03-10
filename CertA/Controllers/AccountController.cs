using CertA.Models;
using CertA.Options;
using CertA.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using AuthService = CertA.Services.IAuthenticationService;

namespace CertA.Controllers
{
    public class AccountController : Controller
    {
        private readonly IUserService _userService;
        private readonly AuthService _authService;
        private readonly OAuth2Options _oauth2Options;
        private readonly ILogger<AccountController> _logger;

        public AccountController(
            IUserService userService,
            AuthService authService,
            IOptions<OAuth2Options> oauth2Options,
            ILogger<AccountController> logger)
        {
            _userService = userService;
            _authService = authService;
            _oauth2Options = oauth2Options.Value;
            _logger = logger;
        }

        [Authorize]
        public IActionResult Profile()
        {
            return Redirect("/account/profile");
        }

        [Authorize]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Profile(ProfileViewModel model)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userId))
            {
                return Redirect("/login");
            }

            var user = await _userService.GetUserByIdAsync(userId);
            if (user == null)
            {
                return Redirect("/login");
            }

            if (!ModelState.IsValid)
            {
                return Redirect("/account/profile?error=" + Uri.EscapeDataString("Invalid input."));
            }

            user.FirstName = model.FirstName;
            user.LastName = model.LastName;
            user.Organization = model.Organization;

            var updated = await _userService.UpdateUserAsync(user);
            if (updated)
            {
                _logger.LogInformation("User {Email} updated their profile", user.Email);
                return Redirect("/account/profile");
            }

            return Redirect("/account/profile?error=" + Uri.EscapeDataString("Failed to update profile."));
        }

        [Authorize]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                TempData["ErrorMessage"] = "Please correct the errors below.";
                return RedirectToAction("Profile");
            }

            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userId))
            {
                return RedirectToAction("Login");
            }

            var user = await _userService.GetUserByIdAsync(userId);
            if (user == null)
            {
                return RedirectToAction("Login");
            }

            var result = await _userService.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword);
            if (result)
            {
                TempData["SuccessMessage"] = "Password changed successfully!";
                _logger.LogInformation("User {Email} changed their password", user.Email);
            }
            else
            {
                TempData["ErrorMessage"] = "Failed to change password. Please check your current password.";
            }

            return RedirectToAction("Profile");
        }

        [AllowAnonymous]
        [HttpGet]
        public IActionResult AccessDenied(string? message = null)
        {
            var q = string.IsNullOrEmpty(message) ? "" : "?message=" + Uri.EscapeDataString(message);
            return Redirect("/access-denied" + q);
        }

        /// <summary>Returns 200 HTML with meta refresh. Use instead of 302 so browser processes Set-Cookie before navigating (fixes Playwright).</summary>
        private static IActionResult SignInCompleteHtml(string dest)
        {
            var escaped = dest.Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;");
            return new ContentResult
            {
                Content = $"<!DOCTYPE html><html><head><meta http-equiv=\"refresh\" content=\"0;url={escaped}\"/></head><body>Signing in...</body></html>",
                ContentType = "text/html; charset=utf-8",
                StatusCode = 200
            };
        }

        /// <summary>OIDC post-signin: HTML response ensures browser processes Set-Cookie before SPA. Fixes Playwright cookie-after-redirect.</summary>
        [AllowAnonymous]
        [HttpGet]
        public IActionResult SignInComplete(string? returnUrl = null)
        {
            var dest = !string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl) ? returnUrl : "/";
            return SignInCompleteHtml(dest);
        }

        /// <summary>Redirects to SPA /login. SPA handles Keycloak (redirect to /api/auth/authorize) or embedded (show form).</summary>
        [AllowAnonymous]
        [HttpGet]
        public IActionResult Login(string? returnUrl = null)
        {
            var q = string.IsNullOrEmpty(returnUrl) ? "" : "?returnUrl=" + Uri.EscapeDataString(returnUrl ?? "");
            return Redirect("/login" + q);
        }

        [AllowAnonymous]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string? returnUrl = null)
        {
        ViewData["ReturnUrl"] = returnUrl;

            if (ModelState.IsValid)
            {
                var user = await _authService.SignInAsync(model.Email, model.Password, model.RememberMe);
                if (user != null)
                {
                    var principal = await _authService.CreateClaimsPrincipalAsync(user);
                    var authProperties = new AuthenticationProperties
                    {
                        IsPersistent = model.RememberMe,
                        ExpiresUtc = model.RememberMe ? DateTimeOffset.UtcNow.AddDays(30) : DateTimeOffset.UtcNow.AddHours(12)
                    };
                    await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal, authProperties);

                    if (_oauth2Options.Enabled)
                    {
                        var roles = await _userService.GetUserRolesAsync(user.Id);
                        var hasAdmin = roles.Any(r => string.Equals(r, "Admin", StringComparison.OrdinalIgnoreCase));
                        if (!hasAdmin)
                        {
                            _logger.LogWarning("User {Email} has no Admin role; redirecting to access-denied.", model.Email);
                            return Redirect("/access-denied?message=" + Uri.EscapeDataString("Admin role required."));
                        }
                    }
                    var redirectUrl = !string.IsNullOrEmpty(model.ReturnUrl) ? model.ReturnUrl : returnUrl;
                    _logger.LogInformation("User logged in: {Email} redirecting to {RedirectUrl}", model.Email, redirectUrl ?? "(null)");
                    return RedirectToLocal(redirectUrl);
                }
                else
                {
                    return Redirect("/login?error=" + Uri.EscapeDataString("Invalid login attempt."));
                }
            }

            return Redirect("/login?error=" + Uri.EscapeDataString("Invalid input."));
        }

        [HttpGet]
        public IActionResult Register(string? returnUrl = null)
        {
            var q = string.IsNullOrEmpty(returnUrl) ? "" : "?returnUrl=" + Uri.EscapeDataString(returnUrl ?? "");
            return Redirect("/register" + q);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model, string? returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;

            if (ModelState.IsValid)
            {
                var user = new ApplicationUser
                {
                    UserName = model.Email,
                    Email = model.Email,
                    FirstName = model.FirstName,
                    LastName = model.LastName,
                    Organization = model.Organization
                };

                var created = await _userService.CreateUserAsync(user, model.Password);
                if (created)
                {
                    _logger.LogInformation("User created a new account with password: {Email}", model.Email);

                    var principal = await _authService.CreateClaimsPrincipalAsync(user);
                    await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);
                    
                    var redirectUrl = !string.IsNullOrEmpty(model.ReturnUrl) ? model.ReturnUrl : returnUrl;
                    return RedirectToLocal(redirectUrl);
                }
                else
                {
                    return Redirect("/register?error=" + Uri.EscapeDataString("Failed to create account. Email may already be in use."));
                }
            }

            return Redirect("/register?error=" + Uri.EscapeDataString("Invalid input."));
        }

        [AllowAnonymous]
        [HttpGet]
        [ActionName("Logout")]
        public IActionResult LogoutGet() => StatusCode(405);

        [AllowAnonymous]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            _logger.LogInformation("User logged out.");
            if (_oauth2Options.Enabled && !_oauth2Options.UseEmbedded)
            {
                await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                var redirectUri = $"{Request.Scheme}://{Request.Host}/";
                var authority = _oauth2Options.Authority.TrimEnd('/');
                var logoutUrl = $"{authority}/protocol/openid-connect/logout?client_id={Uri.EscapeDataString(_oauth2Options.ClientId)}&post_logout_redirect_uri={Uri.EscapeDataString(redirectUri)}";
                return Redirect(logoutUrl);
            }
            return SignOut(
                new AuthenticationProperties { RedirectUri = "/login" },
                CookieAuthenticationDefaults.AuthenticationScheme);
        }

        private IActionResult RedirectToLocal(string? returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            else
            {
                return RedirectToAction("Index", "Home");
            }
        }
    }

    public class LoginViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; } = string.Empty;

        [Display(Name = "Remember me?")]
        public bool RememberMe { get; set; }

        public string? ReturnUrl { get; set; }
    }

    public class RegisterViewModel
    {
        [Required]
        [Display(Name = "First Name")]
        public string FirstName { get; set; } = string.Empty;

        [Required]
        [Display(Name = "Last Name")]
        public string LastName { get; set; } = string.Empty;

        [Required]
        [EmailAddress]
        [Display(Name = "Email")]
        public string Email { get; set; } = string.Empty;

        [Display(Name = "Organization")]
        public string? Organization { get; set; }

        [Required]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; } = string.Empty;

        [DataType(DataType.Password)]
        [Display(Name = "Confirm password")]
        [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; } = string.Empty;

        public string? ReturnUrl { get; set; }
    }

    public class ProfileViewModel
    {
        [Required]
        [Display(Name = "First Name")]
        public string FirstName { get; set; } = string.Empty;

        [Required]
        [Display(Name = "Last Name")]
        public string LastName { get; set; } = string.Empty;

        [Required]
        [EmailAddress]
        [Display(Name = "Email")]
        public string Email { get; set; } = string.Empty;

        [Display(Name = "Organization")]
        public string? Organization { get; set; }

        [Display(Name = "Account Created")]
        public DateTime CreatedDate { get; set; }

        [Display(Name = "Account Status")]
        public bool IsActive { get; set; }
    }

    public class ChangePasswordViewModel
    {
        [Required]
        [DataType(DataType.Password)]
        [Display(Name = "Current Password")]
        public string CurrentPassword { get; set; } = string.Empty;

        [Required]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [Display(Name = "New Password")]
        public string NewPassword { get; set; } = string.Empty;

        [DataType(DataType.Password)]
        [Display(Name = "Confirm New Password")]
        [Compare("NewPassword", ErrorMessage = "The new password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; } = string.Empty;
    }
}