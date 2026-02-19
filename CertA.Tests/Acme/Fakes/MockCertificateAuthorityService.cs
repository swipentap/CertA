using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CertA.Models;
using CertA.Services;

namespace CertA.Tests.Acme.Fakes;

public sealed class MockCertificateAuthorityService : ICertificateAuthorityService
{
    public Task<CertificateAuthority?> GetActiveCAAsync() => Task.FromResult<CertificateAuthority?>(null);
    public Task<CertificateAuthority> CreateRootCAAsync(string name, string commonName, string organization, string country, string state, string locality) =>
        throw new NotSupportedException();
    public Task<bool> DeactivateCAAsync(int caId) => Task.FromResult(false);
    public Task<List<CertificateAuthority>> GetAllCAsAsync() => Task.FromResult(new List<CertificateAuthority>());

    public Task<X509Certificate2> SignCertificateAsync(CertificateRequest request, string commonName, string? sans, CertificateType type)
    {
        using var caKey = RSA.Create(2048);
        var caSubject = new X500DistinguishedName("CN=Test CA");
        var caRequest = new CertificateRequest(caSubject, caKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        var notBefore = DateTimeOffset.UtcNow;
        var notAfter = notBefore.AddYears(1);
        using var caCert = caRequest.CreateSelfSigned(notBefore, notAfter);
        var serialNumber = new byte[16];
        RandomNumberGenerator.Fill(serialNumber);
        var signedCert = request.Create(caCert, notBefore, notAfter, serialNumber);
        return Task.FromResult(signedCert);
    }
}
