using CertA.Services.Acme;

namespace CertA.Tests.Acme.Fakes;

public sealed class MockAcmeCertificatePersistence : IAcmeCertificatePersistence
{
    public Task<int> SaveAcmeCertificateAsync(
        string commonName,
        string? subjectAlternativeNames,
        string serialNumber,
        DateTime issuedDate,
        DateTime expiryDate,
        string certificatePem,
        string publicKeyPem,
        string userId,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(1);
}
