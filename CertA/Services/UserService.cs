using CertA.Data;
using CertA.Models;
using BCrypt.Net;
using System.Data;
using Dapper;

namespace CertA.Services
{
    public class UserService : IUserService
    {
        private readonly IDatabaseConnectionFactory _connectionFactory;
        private readonly ILogger<UserService> _logger;

        public UserService(IDatabaseConnectionFactory connectionFactory, ILogger<UserService> logger)
        {
            _connectionFactory = connectionFactory;
            _logger = logger;
        }

        public async Task<ApplicationUser?> GetUserByIdAsync(string userId)
        {
            using var connection = await _connectionFactory.CreateConnectionAsync();
            var sql = @"
                SELECT ""Id"", ""UserName"", ""NormalizedUserName"", ""Email"", ""NormalizedEmail"", 
                       ""EmailConfirmed"", ""PasswordHash"", ""SecurityStamp"", ""ConcurrencyStamp"",
                       ""PhoneNumber"", ""PhoneNumberConfirmed"", ""TwoFactorEnabled"", ""LockoutEnd"",
                       ""LockoutEnabled"", ""AccessFailedCount"", ""FirstName"", ""LastName"", 
                       ""Organization"", ""CreatedDate"", ""IsActive""
                FROM ""Users""
                WHERE ""Id"" = @Id";
            
            return await connection.QueryFirstOrDefaultAsync<ApplicationUser>(sql, new { Id = userId });
        }

        public async Task<ApplicationUser?> GetUserByEmailAsync(string email)
        {
            return await GetUserByNormalizedEmailAsync(email.ToUpperInvariant());
        }

        public async Task<ApplicationUser?> GetUserByNormalizedEmailAsync(string normalizedEmail)
        {
            using var connection = await _connectionFactory.CreateConnectionAsync();
            var sql = @"
                SELECT ""Id"", ""UserName"", ""NormalizedUserName"", ""Email"", ""NormalizedEmail"", 
                       ""EmailConfirmed"", ""PasswordHash"", ""SecurityStamp"", ""ConcurrencyStamp"",
                       ""PhoneNumber"", ""PhoneNumberConfirmed"", ""TwoFactorEnabled"", ""LockoutEnd"",
                       ""LockoutEnabled"", ""AccessFailedCount"", ""FirstName"", ""LastName"", 
                       ""Organization"", ""CreatedDate"", ""IsActive""
                FROM ""Users""
                WHERE ""NormalizedEmail"" = @NormalizedEmail";
            
            return await connection.QueryFirstOrDefaultAsync<ApplicationUser>(sql, new { NormalizedEmail = normalizedEmail });
        }

        public async Task<bool> CreateUserAsync(ApplicationUser user, string password)
        {
            using var connection = await _connectionFactory.CreateConnectionAsync();
            connection.Open();

            using var transaction = connection.BeginTransaction();
            try
            {
                // Check if user already exists
                var existing = await GetUserByNormalizedEmailAsync(user.NormalizedEmail ?? user.Email.ToUpperInvariant());
                if (existing != null)
                {
                    return false;
                }

                // Generate ID if not set
                if (string.IsNullOrEmpty(user.Id))
                {
                    user.Id = Guid.NewGuid().ToString();
                }

                // Hash password
                user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(password);
                user.SecurityStamp = Guid.NewGuid().ToString();
                user.ConcurrencyStamp = Guid.NewGuid().ToString();
                user.NormalizedUserName = user.UserName?.ToUpperInvariant();
                user.NormalizedEmail = user.Email.ToUpperInvariant();
                user.CreatedDate = DateTime.UtcNow;

                var sql = @"
                    INSERT INTO ""Users"" (""Id"", ""UserName"", ""NormalizedUserName"", ""Email"", ""NormalizedEmail"", 
                                          ""EmailConfirmed"", ""PasswordHash"", ""SecurityStamp"", ""ConcurrencyStamp"",
                                          ""PhoneNumber"", ""PhoneNumberConfirmed"", ""TwoFactorEnabled"", ""LockoutEnd"",
                                          ""LockoutEnabled"", ""AccessFailedCount"", ""FirstName"", ""LastName"", 
                                          ""Organization"", ""CreatedDate"", ""IsActive"")
                    VALUES (@Id, @UserName, @NormalizedUserName, @Email, @NormalizedEmail, 
                            @EmailConfirmed, @PasswordHash, @SecurityStamp, @ConcurrencyStamp,
                            @PhoneNumber, @PhoneNumberConfirmed, @TwoFactorEnabled, @LockoutEnd,
                            @LockoutEnabled, @AccessFailedCount, @FirstName, @LastName, 
                            @Organization, @CreatedDate, @IsActive)";

                await connection.ExecuteAsync(sql, user, transaction);
                transaction.Commit();
                return true;
            }
            catch (Exception ex)
            {
                transaction.Rollback();
                _logger.LogError(ex, "Failed to create user {Email}", user.Email);
                return false;
            }
        }

        public async Task<bool> UpdateUserAsync(ApplicationUser user)
        {
            using var connection = await _connectionFactory.CreateConnectionAsync();
            var sql = @"
                UPDATE ""Users""
                SET ""UserName"" = @UserName,
                    ""NormalizedUserName"" = @NormalizedUserName,
                    ""Email"" = @Email,
                    ""NormalizedEmail"" = @NormalizedEmail,
                    ""EmailConfirmed"" = @EmailConfirmed,
                    ""SecurityStamp"" = @SecurityStamp,
                    ""ConcurrencyStamp"" = @ConcurrencyStamp,
                    ""PhoneNumber"" = @PhoneNumber,
                    ""PhoneNumberConfirmed"" = @PhoneNumberConfirmed,
                    ""TwoFactorEnabled"" = @TwoFactorEnabled,
                    ""LockoutEnd"" = @LockoutEnd,
                    ""LockoutEnabled"" = @LockoutEnabled,
                    ""AccessFailedCount"" = @AccessFailedCount,
                    ""FirstName"" = @FirstName,
                    ""LastName"" = @LastName,
                    ""Organization"" = @Organization,
                    ""IsActive"" = @IsActive
                WHERE ""Id"" = @Id";

            var rowsAffected = await connection.ExecuteAsync(sql, user);
            return rowsAffected > 0;
        }

        public async Task<bool> VerifyPasswordAsync(ApplicationUser user, string password)
        {
            if (user == null || string.IsNullOrEmpty(user.PasswordHash))
                return false;

            return BCrypt.Net.BCrypt.Verify(password, user.PasswordHash);
        }

        public async Task<bool> CheckPasswordAsync(ApplicationUser user, string password)
        {
            return await VerifyPasswordAsync(user, password);
        }

        public async Task<bool> ChangePasswordAsync(ApplicationUser user, string currentPassword, string newPassword)
        {
            // Verify current password
            if (!await VerifyPasswordAsync(user, currentPassword))
            {
                return false;
            }

            // Update password
            using var connection = await _connectionFactory.CreateConnectionAsync();
            var newPasswordHash = BCrypt.Net.BCrypt.HashPassword(newPassword);
            var sql = @"UPDATE ""Users"" SET ""PasswordHash"" = @PasswordHash, ""SecurityStamp"" = @SecurityStamp WHERE ""Id"" = @Id";
            
            var rowsAffected = await connection.ExecuteAsync(sql, new 
            { 
                PasswordHash = newPasswordHash, 
                SecurityStamp = Guid.NewGuid().ToString(),
                Id = user.Id 
            });
            
            return rowsAffected > 0;
        }
    }
}