using CertA.Models;
using System.Security.Claims;

namespace CertA.Services
{
    public class AuthenticationService : IAuthenticationService
    {
        private readonly IUserService _userService;
        private readonly ILogger<AuthenticationService> _logger;

        public AuthenticationService(IUserService userService, ILogger<AuthenticationService> logger)
        {
            _userService = userService;
            _logger = logger;
        }

        public async Task<ApplicationUser?> SignInAsync(string email, string password, bool rememberMe)
        {
            var user = await _userService.GetUserByEmailAsync(email);
            if (user == null || !user.IsActive)
            {
                return null;
            }

            var isValid = await _userService.CheckPasswordAsync(user, password);
            if (!isValid)
            {
                return null;
            }

            return user;
        }

        public Task SignOutAsync()
        {
            // Sign out is handled by cookie authentication middleware
            return Task.CompletedTask;
        }

        public Task<ClaimsPrincipal> CreateClaimsPrincipalAsync(ApplicationUser user)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Name, user.UserName ?? user.Email ?? ""),
                new Claim(ClaimTypes.Email, user.Email ?? ""),
            };

            if (!string.IsNullOrEmpty(user.FirstName))
                claims.Add(new Claim(ClaimTypes.GivenName, user.FirstName));
            
            if (!string.IsNullOrEmpty(user.LastName))
                claims.Add(new Claim(ClaimTypes.Surname, user.LastName));

            var identity = new ClaimsIdentity(claims, "Cookies");
            var principal = new ClaimsPrincipal(identity);
            
            return Task.FromResult(principal);
        }
    }
}