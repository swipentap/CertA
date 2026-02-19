using CertA.Data;
using CertA.Models.Acme;
using Dapper;
using System.Data;

namespace CertA.Services.Acme;

public class AcmeStorageService : IAcmeStorageService
{
    private readonly IDatabaseConnectionFactory _connectionFactory;
    private readonly ILogger<AcmeStorageService> _logger;

    public AcmeStorageService(IDatabaseConnectionFactory connectionFactory, ILogger<AcmeStorageService> logger)
    {
        _connectionFactory = connectionFactory;
        _logger = logger;
    }

    public async Task<string> CreateNonceAsync(TimeSpan validity)
    {
        var nonce = Convert.ToBase64String(Guid.NewGuid().ToByteArray()).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var expiresAt = DateTime.UtcNow.Add(validity);
        using var connection = await _connectionFactory.CreateConnectionAsync();
        await connection.ExecuteAsync(@"
            INSERT INTO ""AcmeNonces"" (""Nonce"", ""ExpiresAt"")
            VALUES (@Nonce, @ExpiresAt)",
            new { Nonce = nonce, ExpiresAt = expiresAt });
        return nonce;
    }

    public async Task<bool> ConsumeNonceAsync(string nonce)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync();
        var rows = await connection.ExecuteAsync(@"
            DELETE FROM ""AcmeNonces""
            WHERE ""Nonce"" = @Nonce AND ""ExpiresAt"" > @Now",
            new { Nonce = nonce, Now = DateTime.UtcNow });
        return rows > 0;
    }

    public async Task<AcmeAccount?> GetAccountByKeyIdAsync(string keyId)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync();
        return await connection.QueryFirstOrDefaultAsync<AcmeAccount>(@"
            SELECT ""Id"", ""AccountId"", ""KeyJwk"", ""KeyThumbprint"", ""Status"", ""CreatedAt""
            FROM ""AcmeAccounts""
            WHERE ""AccountId"" = @AccountId",
            new { AccountId = keyId });
    }

    public async Task<AcmeAccount?> GetAccountByThumbprintAsync(string thumbprint)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync();
        return await connection.QueryFirstOrDefaultAsync<AcmeAccount>(@"
            SELECT ""Id"", ""AccountId"", ""KeyJwk"", ""KeyThumbprint"", ""Status"", ""CreatedAt""
            FROM ""AcmeAccounts""
            WHERE ""KeyThumbprint"" = @Thumbprint",
            new { Thumbprint = thumbprint });
    }

    public async Task<AcmeAccount> CreateAccountAsync(string accountId, string keyJwkJson, string keyThumbprint)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync();
        var id = await connection.QuerySingleAsync<int>(@"
            INSERT INTO ""AcmeAccounts"" (""AccountId"", ""KeyJwk"", ""KeyThumbprint"", ""Status"")
            VALUES (@AccountId, @KeyJwk::jsonb, @KeyThumbprint, 'valid')
            RETURNING ""Id""",
            new { AccountId = accountId, KeyJwk = keyJwkJson, KeyThumbprint = keyThumbprint });
        var created = await GetAccountByKeyIdAsync(accountId);
        return created!;
    }

    public async Task<AcmeOrder?> GetOrderAsync(string orderId)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync();
        return await connection.QueryFirstOrDefaultAsync<AcmeOrder>(@"
            SELECT ""Id"", ""OrderId"", ""AccountId"", ""Identifiers"", ""Status"", ""Expires"", ""CertificateId"", ""CertificatePem"", ""CreatedAt""
            FROM ""AcmeOrders""
            WHERE ""OrderId"" = @OrderId",
            new { OrderId = orderId });
    }

    public async Task<AcmeOrder> CreateOrderAsync(string orderId, string accountId, string identifiersJson, DateTime expires)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync();
        await connection.ExecuteAsync(@"
            INSERT INTO ""AcmeOrders"" (""OrderId"", ""AccountId"", ""Identifiers"", ""Status"", ""Expires"")
            VALUES (@OrderId, @AccountId, @Identifiers::jsonb, 'pending', @Expires)",
            new { OrderId = orderId, AccountId = accountId, Identifiers = identifiersJson, Expires = expires });
        return (await GetOrderAsync(orderId))!;
    }

    public async Task UpdateOrderStatusAsync(string orderId, string status, string? certificatePem = null, int? certificateId = null)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync();
        await connection.ExecuteAsync(@"
            UPDATE ""AcmeOrders""
            SET ""Status"" = @Status, ""CertificatePem"" = COALESCE(@CertificatePem, ""CertificatePem""), ""CertificateId"" = COALESCE(@CertificateId, ""CertificateId"")
            WHERE ""OrderId"" = @OrderId",
            new { OrderId = orderId, Status = status, CertificatePem = certificatePem, CertificateId = certificateId });
    }

    public async Task<AcmeAuthorization?> GetAuthorizationAsync(string authId)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync();
        return await connection.QueryFirstOrDefaultAsync<AcmeAuthorization>(@"
            SELECT ""Id"", ""AuthId"", ""OrderId"", ""IdentifierType"", ""IdentifierValue"", ""Status"", ""Expires"", ""CreatedAt""
            FROM ""AcmeAuthorizations""
            WHERE ""AuthId"" = @AuthId",
            new { AuthId = authId });
    }

    public async Task<AcmeAuthorization> CreateAuthorizationAsync(string authId, string orderId, string identifierType, string identifierValue, DateTime expires)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync();
        await connection.ExecuteAsync(@"
            INSERT INTO ""AcmeAuthorizations"" (""AuthId"", ""OrderId"", ""IdentifierType"", ""IdentifierValue"", ""Status"", ""Expires"")
            VALUES (@AuthId, @OrderId, @IdentifierType, @IdentifierValue, 'pending', @Expires)",
            new { AuthId = authId, OrderId = orderId, IdentifierType = identifierType, IdentifierValue = identifierValue, Expires = expires });
        return (await GetAuthorizationAsync(authId))!;
    }

    public async Task UpdateAuthorizationStatusAsync(string authId, string status)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync();
        await connection.ExecuteAsync(@"
            UPDATE ""AcmeAuthorizations"" SET ""Status"" = @Status WHERE ""AuthId"" = @AuthId",
            new { AuthId = authId, Status = status });
    }

    public async Task<AcmeChallenge?> GetChallengeAsync(string challengeId)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync();
        return await connection.QueryFirstOrDefaultAsync<AcmeChallenge>(@"
            SELECT ""Id"", ""ChallengeId"", ""AuthId"", ""Type"", ""Token"", ""KeyAuthorization"", ""Status"", ""ValidatedAt"", ""CreatedAt""
            FROM ""AcmeChallenges""
            WHERE ""ChallengeId"" = @ChallengeId",
            new { ChallengeId = challengeId });
    }

    public async Task<AcmeChallenge> CreateChallengeAsync(string challengeId, string authId, string type, string token, string keyAuthorization)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync();
        await connection.ExecuteAsync(@"
            INSERT INTO ""AcmeChallenges"" (""ChallengeId"", ""AuthId"", ""Type"", ""Token"", ""KeyAuthorization"", ""Status"")
            VALUES (@ChallengeId, @AuthId, @Type, @Token, @KeyAuthorization, 'pending')",
            new { ChallengeId = challengeId, AuthId = authId, Type = type, Token = token, KeyAuthorization = keyAuthorization });
        return (await GetChallengeAsync(challengeId))!;
    }

    public async Task UpdateChallengeStatusAsync(string challengeId, string status, DateTime? validatedAt = null)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync();
        await connection.ExecuteAsync(@"
            UPDATE ""AcmeChallenges"" SET ""Status"" = @Status, ""ValidatedAt"" = @ValidatedAt WHERE ""ChallengeId"" = @ChallengeId",
            new { ChallengeId = challengeId, Status = status, ValidatedAt = validatedAt });
    }

    public async Task<List<AcmeAuthorization>> GetAuthorizationsForOrderAsync(string orderId)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync();
        var list = await connection.QueryAsync<AcmeAuthorization>(@"
            SELECT ""Id"", ""AuthId"", ""OrderId"", ""IdentifierType"", ""IdentifierValue"", ""Status"", ""Expires"", ""CreatedAt""
            FROM ""AcmeAuthorizations""
            WHERE ""OrderId"" = @OrderId",
            new { OrderId = orderId });
        return list.ToList();
    }

    public async Task<List<AcmeChallenge>> GetChallengesForAuthAsync(string authId)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync();
        var list = await connection.QueryAsync<AcmeChallenge>(@"
            SELECT ""Id"", ""ChallengeId"", ""AuthId"", ""Type"", ""Token"", ""KeyAuthorization"", ""Status"", ""ValidatedAt"", ""CreatedAt""
            FROM ""AcmeChallenges""
            WHERE ""AuthId"" = @AuthId",
            new { AuthId = authId });
        return list.ToList();
    }
}
