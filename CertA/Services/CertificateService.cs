using CertA.Data;
using CertA.Models;
using System.Data;
using Dapper;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Numerics;

namespace CertA.Services
{
    public interface ICertificateService
    {
        Task<List<CertificateEntity>> ListAsync(string userId);
        Task<CertificateEntity?> GetAsync(int id, string userId);
        Task<CertificateEntity> CreateAsync(string commonName, string? sans, CertificateType type, string userId);
        Task<CertificateEntity> CreateWildcardAsync(string domain, string? additionalSans, string userId);
        Task<bool> DeleteAsync(int id, string userId);
        Task<byte[]> GetPrivateKeyPemAsync(int id, string userId);
        Task<byte[]> GetPublicKeyPemAsync(int id, string userId);
        Task<byte[]> GetCertificatePemAsync(int id, string userId);
        Task<byte[]> GetPfxAsync(int id, string password, string userId);
        Task<byte[]> GetHAProxyFormatAsync(int id, string userId);
        Task<List<CertificateEntity>> GetExpiringCertificatesAsync(int daysThreshold = 30);
    }

    public class CertificateService : ICertificateService
    {
        private readonly IDatabaseConnectionFactory _connectionFactory;
        private readonly ICertificateAuthorityService _caService;
        private readonly ILogger<CertificateService> _logger;

        public CertificateService(IDatabaseConnectionFactory connectionFactory, ICertificateAuthorityService caService, ILogger<CertificateService> logger)
        {
            _connectionFactory = connectionFactory;
            _caService = caService;
            _logger = logger;
        }

        public async Task<List<CertificateEntity>> ListAsync(string userId)
        {
            using var connection = await _connectionFactory.CreateConnectionAsync();
            var sql = @"
                SELECT ""Id"", ""CommonName"", ""SubjectAlternativeNames"", ""SerialNumber"", 
                       ""IssuedDate"", ""ExpiryDate"", ""Status"", ""Type"", 
                       ""CertificatePem"", ""PublicKeyPem"", ""PrivateKeyPem"", ""UserId""
                FROM ""Certificates""
                WHERE ""UserId"" = @UserId
                ORDER BY ""Id"" DESC";
            
            return (await connection.QueryAsync<CertificateEntity>(sql, new { UserId = userId })).ToList();
        }

        public async Task<CertificateEntity?> GetAsync(int id, string userId)
        {
            using var connection = await _connectionFactory.CreateConnectionAsync();
            var sql = @"
                SELECT ""Id"", ""CommonName"", ""SubjectAlternativeNames"", ""SerialNumber"", 
                       ""IssuedDate"", ""ExpiryDate"", ""Status"", ""Type"", 
                       ""CertificatePem"", ""PublicKeyPem"", ""PrivateKeyPem"", ""UserId""
                FROM ""Certificates""
                WHERE ""Id"" = @Id AND ""UserId"" = @UserId";
            
            return await connection.QueryFirstOrDefaultAsync<CertificateEntity>(sql, new { Id = id, UserId = userId });
        }

        public async Task<CertificateEntity> CreateAsync(string commonName, string? sans, CertificateType type, string userId)
        {
            // Check if we have an active CA
            var ca = await _caService.GetActiveCAAsync();
            if (ca == null)
            {
                // Create a default CA if none exists
                ca = await _caService.CreateRootCAAsync(
                    "CertA Root CA",
                    "CertA Root CA",
                    "CertA Organization",
                    "US",
                    "California",
                    "San Francisco"
                );
            }

            // Generate a new key pair for the certificate
            using var rsa = RSA.Create(2048);
            var publicKeyPem = rsa.ExportRSAPublicKeyPem();
            var privateKeyPem = rsa.ExportRSAPrivateKeyPem();

            // Create certificate request
            var subject = new X500DistinguishedName($"CN={commonName},O=CertA Organization,C=US");
            var request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            // Sign the certificate with our CA
            var signedCertificate = await _caService.SignCertificateAsync(request, commonName, sans, type);
            var certificatePem = signedCertificate.ExportCertificatePem();

            var notBefore = DateTime.UtcNow;
            var notAfter = notBefore.AddYears(1);
            var serialNumber = GenerateSerialNumber();

            var entity = new CertificateEntity
            {
                CommonName = commonName,
                SubjectAlternativeNames = sans,
                SerialNumber = serialNumber.ToString("X"),
                IssuedDate = notBefore,
                ExpiryDate = notAfter,
                Status = CertificateStatus.Issued,
                Type = type,
                CertificatePem = certificatePem,
                PublicKeyPem = publicKeyPem,
                PrivateKeyPem = privateKeyPem,
                UserId = userId
            };

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
            
            var newId = await connection.QuerySingleAsync<int>(insertSql, entity);
            entity.Id = newId;
            
            _logger.LogInformation("Created {Type} certificate {Serial} for {CN} by user {UserId}", type, serialNumber, commonName, userId);
            return entity;
        }

        public async Task<CertificateEntity> CreateWildcardAsync(string domain, string? additionalSans, string userId)
        {
            // Ensure domain doesn't start with wildcard
            if (domain.StartsWith("*."))
            {
                domain = domain.Substring(2);
            }

            // Create wildcard common name
            var wildcardCommonName = $"*.{domain}";

            // Combine additional SANs
            var allSans = new List<string> { wildcardCommonName };
            if (!string.IsNullOrEmpty(additionalSans))
            {
                allSans.AddRange(additionalSans.Split(',', StringSplitOptions.RemoveEmptyEntries)
                    .Select(s => s.Trim())
                    .Where(s => !string.IsNullOrEmpty(s)));
            }

            var sansString = string.Join(",", allSans);

            return await CreateAsync(wildcardCommonName, sansString, CertificateType.Wildcard, userId);
        }

        public async Task<List<CertificateEntity>> GetExpiringCertificatesAsync(int daysThreshold = 30)
        {
            var thresholdDate = DateTime.UtcNow.AddDays(daysThreshold);
            
            using var connection = await _connectionFactory.CreateConnectionAsync();
            var sql = @"
                SELECT ""Id"", ""CommonName"", ""SubjectAlternativeNames"", ""SerialNumber"", 
                       ""IssuedDate"", ""ExpiryDate"", ""Status"", ""Type"", 
                       ""CertificatePem"", ""PublicKeyPem"", ""PrivateKeyPem"", ""UserId""
                FROM ""Certificates""
                WHERE ""Status"" = @Status 
                  AND ""ExpiryDate"" <= @ThresholdDate 
                  AND ""ExpiryDate"" > @Now
                ORDER BY ""ExpiryDate""";
            
            return (await connection.QueryAsync<CertificateEntity>(sql, new 
            { 
                Status = (int)CertificateStatus.Issued, 
                ThresholdDate = thresholdDate, 
                Now = DateTime.UtcNow 
            })).ToList();
        }

        public async Task<bool> DeleteAsync(int id, string userId)
        {
            using var connection = await _connectionFactory.CreateConnectionAsync();
            var sql = @"DELETE FROM ""Certificates"" WHERE ""Id"" = @Id AND ""UserId"" = @UserId";
            
            var rowsAffected = await connection.ExecuteAsync(sql, new { Id = id, UserId = userId });
            
            if (rowsAffected > 0)
            {
                _logger.LogInformation("Deleted certificate {Id} for user {UserId}", id, userId);
                return true;
            }
            
            return false;
        }

        public async Task<byte[]> GetPrivateKeyPemAsync(int id, string userId)
        {
            var cert = await GetAsync(id, userId);
            if (cert?.PrivateKeyPem == null) throw new InvalidOperationException("Certificate or private key not found");
            return Encoding.UTF8.GetBytes(cert.PrivateKeyPem);
        }

        public async Task<byte[]> GetPublicKeyPemAsync(int id, string userId)
        {
            var cert = await GetAsync(id, userId);
            if (cert?.PublicKeyPem == null) throw new InvalidOperationException("Certificate or public key not found");
            return Encoding.UTF8.GetBytes(cert.PublicKeyPem);
        }

        public async Task<byte[]> GetCertificatePemAsync(int id, string userId)
        {
            var cert = await GetAsync(id, userId);
            if (cert?.CertificatePem == null) throw new InvalidOperationException("Certificate not found");
            return Encoding.UTF8.GetBytes(cert.CertificatePem);
        }

        public async Task<byte[]> GetPfxAsync(int id, string password, string userId)
        {
            var cert = await GetAsync(id, userId);
            if (cert?.CertificatePem == null || cert?.PrivateKeyPem == null)
                throw new InvalidOperationException("Certificate or private key not found");

            try
            {
                // Create X509Certificate2 from PEM
                var certificate = X509Certificate2.CreateFromPem(cert.CertificatePem, cert.PrivateKeyPem);

                // Export as PKCS#12
                var pfxBytes = certificate.Export(X509ContentType.Pfx, password);

                _logger.LogInformation("Generated PFX for certificate {Id} by user {UserId}", id, userId);
                return pfxBytes;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to generate PFX for certificate {Id} by user {UserId}", id, userId);
                throw new InvalidOperationException("Failed to generate PFX file");
            }
        }

        public async Task<byte[]> GetHAProxyFormatAsync(int id, string userId)
        {
            var cert = await GetAsync(id, userId);
            if (cert?.CertificatePem == null || cert?.PrivateKeyPem == null)
                throw new InvalidOperationException("Certificate or private key not found");

            try
            {
                // Get CA certificate
                var ca = await _caService.GetActiveCAAsync();
                if (ca == null)
                    throw new InvalidOperationException("Certificate Authority not found");

                // HAProxy format: Private Key + Certificate + CA Certificate
                var haproxyContent = new StringBuilder();
                
                // Add private key
                haproxyContent.AppendLine(cert.PrivateKeyPem);
                
                // Add certificate
                haproxyContent.AppendLine(cert.CertificatePem);
                
                // Add CA certificate
                haproxyContent.AppendLine(ca.CertificatePem);

                _logger.LogInformation("Generated HAProxy format for certificate {Id} by user {UserId}", id, userId);
                return Encoding.UTF8.GetBytes(haproxyContent.ToString());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to generate HAProxy format for certificate {Id} by user {UserId}", id, userId);
                throw new InvalidOperationException("Failed to generate HAProxy format");
            }
        }

        private static BigInteger GenerateSerialNumber()
        {
            var random = new byte[20];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(random);
            return new BigInteger(random, true, true);
        }
    }
}


