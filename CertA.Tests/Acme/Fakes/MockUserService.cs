using CertA.Models;
using CertA.Services;

namespace CertA.Tests.Acme.Fakes;

public sealed class MockUserService : IUserService
{
    private readonly string _adminId;

    public MockUserService(string? adminId = null)
    {
        _adminId = adminId ?? "test-admin-id";
    }

    public Task<ApplicationUser?> GetUserByEmailAsync(string email)
    {
        if (string.Equals(email, "admin@certa.local", StringComparison.OrdinalIgnoreCase))
            return Task.FromResult<ApplicationUser?>(new ApplicationUser { Id = _adminId, Email = email, UserName = email });
        return Task.FromResult<ApplicationUser?>(null);
    }

    public Task<ApplicationUser?> GetUserByIdAsync(string userId) =>
        string.Equals(userId, _adminId, StringComparison.Ordinal) ? GetUserByEmailAsync("admin@certa.local") : Task.FromResult<ApplicationUser?>(null);
    public Task<ApplicationUser?> GetUserByNormalizedEmailAsync(string normalizedEmail) => GetUserByEmailAsync(normalizedEmail);
    public Task<bool> CreateUserAsync(ApplicationUser user, string password) => Task.FromResult(false);
    public Task<bool> UpdateUserAsync(ApplicationUser user) => Task.FromResult(false);
    public Task<bool> VerifyPasswordAsync(ApplicationUser user, string password) => Task.FromResult(false);
    public Task<bool> ChangePasswordAsync(ApplicationUser user, string currentPassword, string newPassword) => Task.FromResult(false);
    public Task<bool> CheckPasswordAsync(ApplicationUser user, string password) => Task.FromResult(false);
    public Task<IList<string>> GetUserRolesAsync(string userId) => Task.FromResult<IList<string>>(new List<string>());
    public Task EnsureUserInRoleAsync(string userId, string roleName) => Task.CompletedTask;
}
