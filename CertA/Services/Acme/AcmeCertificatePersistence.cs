using CertA.Data;
using Dapper;
using System.Data;

namespace CertA.Services.Acme;

public class AcmeCertificatePersistence : IAcmeCertificatePersistence
{
    private readonly IDatabaseConnectionFactory _connectionFactory;

    public AcmeCertificatePersistence(IDatabaseConnectionFactory connectionFactory)
    {
        _connectionFactory = connectionFactory;
    }

    public async Task<int> SaveAcmeCertificateAsync(
        string commonName,
        string? subjectAlternativeNames,
        string serialNumber,
        DateTime issuedDate,
        DateTime expiryDate,
        string certificatePem,
        string publicKeyPem,
        string userId,
        CancellationToken cancellationToken = default)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync();
        connection.Open();
        var insertSql = @"
            INSERT INTO ""Certificates"" (""CommonName"", ""SubjectAlternativeNames"", ""SerialNumber"",
                ""IssuedDate"", ""ExpiryDate"", ""Status"", ""Type"",
                ""CertificatePem"", ""PublicKeyPem"", ""PrivateKeyPem"", ""UserId"")
            VALUES (@CommonName, @SubjectAlternativeNames, @SerialNumber,
                @IssuedDate, @ExpiryDate, @Status, @Type,
                @CertificatePem, @PublicKeyPem, @PrivateKeyPem, @UserId)
            RETURNING ""Id""";
        var certId = await connection.QuerySingleAsync<int>(insertSql, new
        {
            CommonName = commonName,
            SubjectAlternativeNames = subjectAlternativeNames,
            SerialNumber = serialNumber,
            IssuedDate = issuedDate,
            ExpiryDate = expiryDate,
            Status = (int)Models.CertificateStatus.Issued,
            Type = (int)Models.CertificateType.Server,
            CertificatePem = certificatePem,
            PublicKeyPem = publicKeyPem,
            PrivateKeyPem = "", // ACME client holds private key
            UserId = userId
        });
        return certId;
    }
}
