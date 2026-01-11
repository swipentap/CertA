using CertA.Models;

namespace CertA.Services
{
    public interface IUserService
    {
        Task<ApplicationUser?> GetUserByIdAsync(string userId);
        Task<ApplicationUser?> GetUserByEmailAsync(string email);
        Task<ApplicationUser?> GetUserByNormalizedEmailAsync(string normalizedEmail);
        Task<bool> CreateUserAsync(ApplicationUser user, string password);
        Task<bool> UpdateUserAsync(ApplicationUser user);
        Task<bool> VerifyPasswordAsync(ApplicationUser user, string password);
        Task<bool> ChangePasswordAsync(ApplicationUser user, string currentPassword, string newPassword);
        Task<bool> CheckPasswordAsync(ApplicationUser user, string password);
    }
}