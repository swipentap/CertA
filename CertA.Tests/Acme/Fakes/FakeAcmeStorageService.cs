using System.Collections.Concurrent;
using CertA.Models.Acme;
using CertA.Services.Acme;

namespace CertA.Tests.Acme.Fakes;

public sealed class FakeAcmeStorageService : IAcmeStorageService
{
    private readonly ConcurrentDictionary<string, string> _nonces = new();
    private readonly ConcurrentDictionary<string, AcmeAccount> _accountsByKeyId = new();
    private readonly ConcurrentDictionary<string, AcmeAccount> _accountsByThumbprint = new();
    private readonly ConcurrentDictionary<string, AcmeOrder> _orders = new();
    private readonly ConcurrentDictionary<string, AcmeAuthorization> _authorizations = new();
    private readonly ConcurrentDictionary<string, AcmeChallenge> _challenges = new();

    public Task<string> CreateNonceAsync(TimeSpan validity)
    {
        var nonce = Guid.NewGuid().ToString("N");
        _nonces[nonce] = (DateTime.UtcNow + validity).ToString("O");
        return Task.FromResult(nonce);
    }

    public Task<bool> ConsumeNonceAsync(string nonce)
    {
        var removed = _nonces.TryRemove(nonce, out _);
        return Task.FromResult(removed);
    }

    public Task<AcmeAccount?> GetAccountByKeyIdAsync(string keyId) =>
        Task.FromResult(_accountsByKeyId.TryGetValue(keyId, out var a) ? a : null);

    public Task<AcmeAccount?> GetAccountByThumbprintAsync(string thumbprint) =>
        Task.FromResult(_accountsByThumbprint.TryGetValue(thumbprint, out var a) ? a : null);

    public Task<AcmeAccount> CreateAccountAsync(string accountId, string keyJwkJson, string keyThumbprint)
    {
        var a = new AcmeAccount
        {
            AccountId = accountId,
            KeyJwk = keyJwkJson,
            KeyThumbprint = keyThumbprint,
            Status = "valid",
            CreatedAt = DateTime.UtcNow
        };
        _accountsByKeyId[accountId] = a;
        _accountsByThumbprint[keyThumbprint] = a;
        return Task.FromResult(a);
    }

    public Task<AcmeOrder?> GetOrderAsync(string orderId) =>
        Task.FromResult(_orders.TryGetValue(orderId, out var o) ? o : null);

    public Task<AcmeOrder> CreateOrderAsync(string orderId, string accountId, string identifiersJson, DateTime expires)
    {
        var o = new AcmeOrder
        {
            OrderId = orderId,
            AccountId = accountId,
            Identifiers = identifiersJson,
            Status = "pending",
            Expires = expires,
            CreatedAt = DateTime.UtcNow
        };
        _orders[orderId] = o;
        return Task.FromResult(o);
    }

    public Task UpdateOrderStatusAsync(string orderId, string status, string? certificatePem = null, int? certificateId = null)
    {
        if (_orders.TryGetValue(orderId, out var o))
        {
            o.Status = status;
            if (certificatePem != null) o.CertificatePem = certificatePem;
            if (certificateId != null) o.CertificateId = certificateId;
        }
        return Task.CompletedTask;
    }

    public Task<AcmeAuthorization?> GetAuthorizationAsync(string authId) =>
        Task.FromResult(_authorizations.TryGetValue(authId, out var a) ? a : null);

    public Task<AcmeAuthorization> CreateAuthorizationAsync(string authId, string orderId, string identifierType, string identifierValue, DateTime expires)
    {
        var a = new AcmeAuthorization
        {
            AuthId = authId,
            OrderId = orderId,
            IdentifierType = identifierType,
            IdentifierValue = identifierValue,
            Status = "pending",
            Expires = expires,
            CreatedAt = DateTime.UtcNow
        };
        _authorizations[authId] = a;
        return Task.FromResult(a);
    }

    public Task UpdateAuthorizationStatusAsync(string authId, string status)
    {
        if (_authorizations.TryGetValue(authId, out var a))
            a.Status = status;
        return Task.CompletedTask;
    }

    public Task<AcmeChallenge?> GetChallengeAsync(string challengeId) =>
        Task.FromResult(_challenges.TryGetValue(challengeId, out var c) ? c : null);

    public Task<AcmeChallenge> CreateChallengeAsync(string challengeId, string authId, string type, string token, string keyAuthorization)
    {
        var c = new AcmeChallenge
        {
            ChallengeId = challengeId,
            AuthId = authId,
            Type = type,
            Token = token,
            KeyAuthorization = keyAuthorization,
            Status = "pending",
            CreatedAt = DateTime.UtcNow
        };
        _challenges[challengeId] = c;
        return Task.FromResult(c);
    }

    public Task UpdateChallengeStatusAsync(string challengeId, string status, DateTime? validatedAt = null)
    {
        if (_challenges.TryGetValue(challengeId, out var c))
        {
            c.Status = status;
            c.ValidatedAt = validatedAt;
        }
        return Task.CompletedTask;
    }

    public Task<List<AcmeAuthorization>> GetAuthorizationsForOrderAsync(string orderId) =>
        Task.FromResult(_authorizations.Values.Where(a => a.OrderId == orderId).ToList());

    public Task<List<AcmeChallenge>> GetChallengesForAuthAsync(string authId) =>
        Task.FromResult(_challenges.Values.Where(c => c.AuthId == authId).ToList());
}
