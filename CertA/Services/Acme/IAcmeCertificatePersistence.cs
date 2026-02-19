namespace CertA.Services.Acme;

/// <summary>
/// Persists an ACME-issued certificate and returns its ID. Used so tests can mock DB persistence.
/// </summary>
public interface IAcmeCertificatePersistence
{
    Task<int> SaveAcmeCertificateAsync(
        string commonName,
        string? subjectAlternativeNames,
        string serialNumber,
        DateTime issuedDate,
        DateTime expiryDate,
        string certificatePem,
        string publicKeyPem,
        string userId,
        CancellationToken cancellationToken = default);
}
