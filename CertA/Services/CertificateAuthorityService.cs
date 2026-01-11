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
    public interface ICertificateAuthorityService
    {
        Task<CertificateAuthority?> GetActiveCAAsync();
        Task<CertificateAuthority> CreateRootCAAsync(string name, string commonName, string organization, string country, string state, string locality);
        Task<X509Certificate2> SignCertificateAsync(CertificateRequest request, string commonName, string? sans, CertificateType type);
        Task<bool> DeactivateCAAsync(int caId);
        Task<List<CertificateAuthority>> GetAllCAsAsync();
    }

    public class CertificateAuthorityService : ICertificateAuthorityService
    {
        private readonly IDatabaseConnectionFactory _connectionFactory;
        private readonly ILogger<CertificateAuthorityService> _logger;

        public CertificateAuthorityService(IDatabaseConnectionFactory connectionFactory, ILogger<CertificateAuthorityService> logger)
        {
            _connectionFactory = connectionFactory;
            _logger = logger;
        }

        public async Task<CertificateAuthority?> GetActiveCAAsync()
        {
            using var connection = await _connectionFactory.CreateConnectionAsync();
            var sql = @"
                SELECT ""Id"", ""Name"", ""CommonName"", ""Organization"", ""Country"", ""State"", ""Locality"",
                       ""CertificatePem"", ""PrivateKeyPem"", ""CreatedDate"", ""ExpiryDate"", ""IsActive""
                FROM ""CertificateAuthorities""
                WHERE ""IsActive"" = true AND ""ExpiryDate"" > @Now
                ORDER BY ""CreatedDate"" DESC
                LIMIT 1";
            
            return await connection.QueryFirstOrDefaultAsync<CertificateAuthority>(sql, new { Now = DateTime.UtcNow });
        }

        public async Task<List<CertificateAuthority>> GetAllCAsAsync()
        {
            using var connection = await _connectionFactory.CreateConnectionAsync();
            var sql = @"
                SELECT ""Id"", ""Name"", ""CommonName"", ""Organization"", ""Country"", ""State"", ""Locality"",
                       ""CertificatePem"", ""PrivateKeyPem"", ""CreatedDate"", ""ExpiryDate"", ""IsActive""
                FROM ""CertificateAuthorities""
                ORDER BY ""CreatedDate"" DESC";
            
            return (await connection.QueryAsync<CertificateAuthority>(sql)).ToList();
        }

        public async Task<CertificateAuthority> CreateRootCAAsync(string name, string commonName, string organization, string country, string state, string locality)
        {
            // Check if there's already an active CA
            var existingCA = await GetActiveCAAsync();
            if (existingCA != null)
            {
                throw new InvalidOperationException($"Cannot create new CA. There is already an active CA: {existingCA.Name} (ID: {existingCA.Id})");
            }

            // Generate CA key pair
            using var rsa = RSA.Create(4096);
            var privateKeyPem = rsa.ExportRSAPrivateKeyPem();
            var publicKeyPem = rsa.ExportRSAPublicKeyPem();

            // Create CA certificate
            var notBefore = DateTime.UtcNow;
            var notAfter = notBefore.AddYears(10); // CA certs typically last longer
            var serialNumber = GenerateSerialNumber();

            var subject = new X500DistinguishedName($"CN={commonName},O={organization},L={locality},ST={state},C={country}");
            var issuer = subject; // Self-signed for root CA

            var request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            // Add CA extensions
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.DigitalSignature, true));
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

            // Create the CA certificate
            var caCertificate = request.CreateSelfSigned(notBefore, notAfter);
            var certificatePem = caCertificate.ExportCertificatePem();

            var ca = new CertificateAuthority
            {
                Name = name,
                CommonName = commonName,
                Organization = organization,
                Country = country,
                State = state,
                Locality = locality,
                CertificatePem = certificatePem,
                PrivateKeyPem = privateKeyPem,
                CreatedDate = notBefore,
                ExpiryDate = notAfter,
                IsActive = true
            };

            using var connection = await _connectionFactory.CreateConnectionAsync();
            connection.Open();
            
            var insertSql = @"
                INSERT INTO ""CertificateAuthorities"" (""Name"", ""CommonName"", ""Organization"", ""Country"", ""State"", ""Locality"",
                                                       ""CertificatePem"", ""PrivateKeyPem"", ""CreatedDate"", ""ExpiryDate"", ""IsActive"")
                VALUES (@Name, @CommonName, @Organization, @Country, @State, @Locality,
                        @CertificatePem, @PrivateKeyPem, @CreatedDate, @ExpiryDate, @IsActive)
                RETURNING ""Id""";
            
            var newId = await connection.QuerySingleAsync<int>(insertSql, ca);
            ca.Id = newId;

            _logger.LogInformation("Created root CA {Name} with serial {Serial}", name, serialNumber);
            return ca;
        }

        public async Task<bool> DeactivateCAAsync(int caId)
        {
            using var connection = await _connectionFactory.CreateConnectionAsync();
            var sql = @"UPDATE ""CertificateAuthorities"" SET ""IsActive"" = false WHERE ""Id"" = @Id";
            
            var rowsAffected = await connection.ExecuteAsync(sql, new { Id = caId });
            
            if (rowsAffected > 0)
            {
                _logger.LogInformation("Deactivated CA (ID: {Id})", caId);
                return true;
            }
            
            return false;
        }

        public async Task<X509Certificate2> SignCertificateAsync(CertificateRequest request, string commonName, string? sans, CertificateType type)
        {
            var ca = await GetActiveCAAsync();
            if (ca == null)
                throw new InvalidOperationException("No active Certificate Authority found");

            // Load CA certificate and private key
            var caCert = X509Certificate2.CreateFromPem(ca.CertificatePem, ca.PrivateKeyPem);
            var caPrivateKey = caCert.GetRSAPrivateKey();
            if (caPrivateKey == null)
                throw new InvalidOperationException("CA private key not found");

            // Validate wildcard certificates
            if (type == CertificateType.Wildcard)
            {
                ValidateWildcardCertificate(commonName, sans);
            }

            // Add SAN extension if provided
            if (!string.IsNullOrEmpty(sans))
            {
                var sanBuilder = new SubjectAlternativeNameBuilder();
                var sanList = sans.Split(',', StringSplitOptions.RemoveEmptyEntries)
                    .Select(s => s.Trim())
                    .Where(s => !string.IsNullOrEmpty(s));

                foreach (var san in sanList)
                {
                    if (Uri.IsWellFormedUriString(san, UriKind.Absolute))
                    {
                        sanBuilder.AddUri(new Uri(san));
                    }
                    else
                    {
                        sanBuilder.AddDnsName(san);
                    }
                }

                request.CertificateExtensions.Add(sanBuilder.Build());
            }

            // Add basic constraints for end entity
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));

            // Add key usage based on certificate type
            var keyUsage = X509KeyUsageFlags.DigitalSignature;
            
            switch (type)
            {
                case CertificateType.Server:
                case CertificateType.Wildcard:
                    keyUsage |= X509KeyUsageFlags.KeyEncipherment;
                    break;
                case CertificateType.Client:
                    keyUsage |= X509KeyUsageFlags.KeyAgreement;
                    break;
                case CertificateType.CodeSigning:
                    keyUsage |= X509KeyUsageFlags.DigitalSignature;
                    break;
                case CertificateType.Email:
                    keyUsage |= X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DataEncipherment;
                    break;
            }

            request.CertificateExtensions.Add(new X509KeyUsageExtension(keyUsage, true));

            // Add extended key usage based on certificate type
            var oids = new List<Oid>();
            
            switch (type)
            {
                case CertificateType.Server:
                case CertificateType.Wildcard:
                    oids.Add(new Oid("1.3.6.1.5.5.7.3.1")); // Server Authentication
                    break;
                case CertificateType.Client:
                    oids.Add(new Oid("1.3.6.1.5.5.7.3.2")); // Client Authentication
                    break;
                case CertificateType.CodeSigning:
                    oids.Add(new Oid("1.3.6.1.5.5.7.3.3")); // Code Signing
                    break;
                case CertificateType.Email:
                    oids.Add(new Oid("1.3.6.1.5.5.7.3.4")); // Email Protection
                    break;
            }

            if (oids.Any())
            {
                var oidCollection = new OidCollection();
                foreach (var oid in oids)
                {
                    oidCollection.Add(oid);
                }
                request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(oidCollection, true));
            }

            // Sign the certificate
            var notBefore = DateTime.UtcNow;
            var notAfter = notBefore.AddYears(1);
            var serialNumber = GenerateSerialNumber();

            var signedCert = request.Create(caCert, notBefore, notAfter, serialNumber.ToByteArray());

            _logger.LogInformation("Signed {Type} certificate for {CN} with serial {Serial}", type, commonName, serialNumber);
            return signedCert;
        }

        private void ValidateWildcardCertificate(string commonName, string? sans)
        {
            // Validate that wildcard certificates follow proper format
            if (!commonName.StartsWith("*."))
            {
                throw new ArgumentException("Wildcard certificates must start with '*.'");
            }

            // Validate wildcard domain format
            var domain = commonName.Substring(2); // Remove "*."
            if (domain.Contains("*"))
            {
                throw new ArgumentException("Wildcard certificates can only have one '*' at the beginning");
            }

            if (domain.StartsWith(".") || domain.EndsWith("."))
            {
                throw new ArgumentException("Invalid wildcard domain format");
            }

            // Validate SANs if provided
            if (!string.IsNullOrEmpty(sans))
            {
                var sanList = sans.Split(',', StringSplitOptions.RemoveEmptyEntries)
                    .Select(s => s.Trim())
                    .Where(s => !string.IsNullOrEmpty(s));

                foreach (var san in sanList)
                {
                    if (san.StartsWith("*."))
                    {
                        var sanDomain = san.Substring(2);
                        if (sanDomain.Contains("*"))
                        {
                            throw new ArgumentException($"Invalid wildcard SAN format: {san}");
                        }
                    }
                }
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
