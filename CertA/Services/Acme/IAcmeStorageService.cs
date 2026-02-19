using CertA.Models.Acme;

namespace CertA.Services.Acme;

public interface IAcmeStorageService
{
    Task<string> CreateNonceAsync(TimeSpan validity);
    Task<bool> ConsumeNonceAsync(string nonce);
    Task<AcmeAccount?> GetAccountByKeyIdAsync(string keyId);
    Task<AcmeAccount?> GetAccountByThumbprintAsync(string thumbprint);
    Task<AcmeAccount> CreateAccountAsync(string accountId, string keyJwkJson, string keyThumbprint);
    Task<AcmeOrder?> GetOrderAsync(string orderId);
    Task<AcmeOrder> CreateOrderAsync(string orderId, string accountId, string identifiersJson, DateTime expires);
    Task UpdateOrderStatusAsync(string orderId, string status, string? certificatePem = null, int? certificateId = null);
    Task<AcmeAuthorization?> GetAuthorizationAsync(string authId);
    Task<AcmeAuthorization> CreateAuthorizationAsync(string authId, string orderId, string identifierType, string identifierValue, DateTime expires);
    Task UpdateAuthorizationStatusAsync(string authId, string status);
    Task<AcmeChallenge?> GetChallengeAsync(string challengeId);
    Task<AcmeChallenge> CreateChallengeAsync(string challengeId, string authId, string type, string token, string keyAuthorization);
    Task UpdateChallengeStatusAsync(string challengeId, string status, DateTime? validatedAt = null);
    Task<List<AcmeAuthorization>> GetAuthorizationsForOrderAsync(string orderId);
    Task<List<AcmeChallenge>> GetChallengesForAuthAsync(string authId);
}
