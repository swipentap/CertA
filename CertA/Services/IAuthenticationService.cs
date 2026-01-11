using CertA.Models;
using System.Security.Claims;

namespace CertA.Services
{
    public interface IAuthenticationService
    {
        Task<ApplicationUser?> SignInAsync(string email, string password, bool rememberMe);
        Task SignOutAsync();
        Task<ClaimsPrincipal> CreateClaimsPrincipalAsync(ApplicationUser user);
    }
}