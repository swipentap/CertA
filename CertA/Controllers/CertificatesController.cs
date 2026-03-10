using CertA.Models;
using CertA.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography.X509Certificates;
using System.Security.Claims;

namespace CertA.Controllers
{
    [Authorize]
    public class CertificatesController : Controller
    {
        private readonly ICertificateService _service;
        private readonly ICertificateAuthorityService _caService;
        private readonly ILogger<CertificatesController> _logger;

        public CertificatesController(
            ICertificateService service,
            ICertificateAuthorityService caService,
            ILogger<CertificatesController> logger)
        {
            _service = service;
            _caService = caService;
            _logger = logger;
        }

        public IActionResult Index()
        {
            return Redirect("/certificates");
        }

        public IActionResult Details(int id)
        {
            return Redirect($"/certificates/{id}");
        }

        public IActionResult Create()
        {
            return Redirect("/certificates/create");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(CreateCertificateVm vm)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userId))
            {
                return Redirect("/login");
            }

            try
            {
                if (!ModelState.IsValid)
                {
                    return Redirect("/certificates/create?error=" + Uri.EscapeDataString("Invalid input."));
                }

                _logger.LogInformation("Creating {Type} certificate for {CommonName} by user {UserId}", vm.Type, vm.CommonName, userId);
                var created = await _service.CreateAsync(vm.CommonName, vm.SubjectAlternativeNames, vm.Type, userId);
                _logger.LogInformation("Successfully created certificate {Id} for {CommonName}", created.Id, created.CommonName);
                return Redirect($"/certificates/{created.Id}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to create {Type} certificate for {CommonName} by user {UserId}: {Message}",
                    vm.Type, vm.CommonName, userId, ex.Message);
                return Redirect("/certificates/create?error=" + Uri.EscapeDataString(ex.Message));
            }
        }

        public async Task<IActionResult> DownloadCertificate(int id)
        {
            try
            {
                var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
                if (string.IsNullOrEmpty(userId))
                {
                    return Redirect("/login");
                }

                var cert = await _service.GetAsync(id, userId);
                if (cert == null) return NotFound();

                var bytes = await _service.GetCertificatePemAsync(id, userId);
                var fileName = $"{cert.CommonName.Replace(" ", "_")}_certificate.pem";
                return File(bytes, "application/x-pem-file", fileName);
            }
            catch (Exception ex)
            {
                return NotFound();
            }
        }

        public async Task<IActionResult> DownloadPrivateKey(int id)
        {
            try
            {
                var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
                if (string.IsNullOrEmpty(userId))
                {
                    return Redirect("/login");
                }

                var cert = await _service.GetAsync(id, userId);
                if (cert == null) return NotFound();

                var bytes = await _service.GetPrivateKeyPemAsync(id, userId);
                var fileName = $"{cert.CommonName.Replace(" ", "_")}_private_key.pem";
                return File(bytes, "application/x-pem-file", fileName);
            }
            catch (Exception ex)
            {
                return NotFound();
            }
        }

        public async Task<IActionResult> DownloadPublicKey(int id)
        {
            try
            {
                var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
                if (string.IsNullOrEmpty(userId))
                {
                    return Redirect("/login");
                }

                var cert = await _service.GetAsync(id, userId);
                if (cert == null) return NotFound();

                var bytes = await _service.GetPublicKeyPemAsync(id, userId);
                var fileName = $"{cert.CommonName.Replace(" ", "_")}_public_key.pem";
                return File(bytes, "application/x-pem-file", fileName);
            }
            catch (Exception ex)
            {
                return NotFound();
            }
        }

        public async Task<IActionResult> DownloadPfx(int id, string password = "password")
        {
            try
            {
                var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
                if (string.IsNullOrEmpty(userId))
                {
                    return Redirect("/login");
                }

                var cert = await _service.GetAsync(id, userId);
                if (cert == null) return NotFound();

                var bytes = await _service.GetPfxAsync(id, password, userId);
                var fileName = $"{cert.CommonName.Replace(" ", "_")}.pfx";
                return File(bytes, "application/x-pkcs12", fileName);
            }
            catch (Exception ex)
            {
                return NotFound();
            }
        }

        public async Task<IActionResult> DownloadHAProxy(int id)
        {
            try
            {
                var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
                if (string.IsNullOrEmpty(userId))
                {
                    return Redirect("/login");
                }

                var cert = await _service.GetAsync(id, userId);
                if (cert == null) return NotFound();

                var bytes = await _service.GetHAProxyFormatAsync(id, userId);
                var fileName = $"{cert.CommonName.Replace(" ", "_")}_haproxy.pem";
                return File(bytes, "application/x-pem-file", fileName);
            }
            catch (Exception ex)
            {
                return NotFound();
            }
        }

        public IActionResult Authority()
        {
            return Redirect("/certificates/authority");
        }

        public async Task<IActionResult> DownloadRootCA()
        {
            try
            {
                var ca = await _caService.GetActiveCAAsync();
                if (ca == null) return NotFound();

                var bytes = System.Text.Encoding.UTF8.GetBytes(ca.CertificatePem);
                var fileName = $"{ca.CommonName.Replace(" ", "_")}_Root_CA.pem";
                return File(bytes, "application/x-pem-file", fileName);
            }
            catch (Exception ex)
            {
                return NotFound();
            }
        }

        public async Task<IActionResult> DownloadRootCAPfx(string password = "password")
        {
            try
            {
                var ca = await _caService.GetActiveCAAsync();
                if (ca == null) return NotFound();

                // Create X509Certificate2 from CA PEM
                var certificate = X509Certificate2.CreateFromPem(ca.CertificatePem, ca.PrivateKeyPem);

                // Export as PKCS#12
                var pfxBytes = certificate.Export(X509ContentType.Pfx, password);

                var fileName = $"{ca.CommonName.Replace(" ", "_")}_Root_CA.pfx";
                return File(pfxBytes, "application/x-pkcs12", fileName);
            }
            catch (Exception ex)
            {
                return NotFound();
            }
        }

        [HttpPost]
        public async Task<IActionResult> Delete(int id)
        {
            try
            {
                var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
                if (string.IsNullOrEmpty(userId))
                {
                    return Redirect("/login");
                }

                var success = await _service.DeleteAsync(id, userId);
                if (success)
                {
                    TempData["SuccessMessage"] = "Certificate deleted successfully.";
                }
                else
                {
                    TempData["ErrorMessage"] = "Certificate not found or could not be deleted.";
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting certificate {Id}", id);
                TempData["ErrorMessage"] = "An error occurred while deleting the certificate.";
            }

            return Redirect("/certificates");
        }
    }

    public class CreateCertificateVm
    {
        [System.ComponentModel.DataAnnotations.Required]
        [System.ComponentModel.DataAnnotations.StringLength(255)]
        public string CommonName { get; set; } = string.Empty;

        public string? SubjectAlternativeNames { get; set; }

        public CertificateType Type { get; set; } = CertificateType.Server;
    }

    public class CertificateDetailsVm
    {
        public CertificateEntity Certificate { get; set; } = null!;
        public string HAProxyContent { get; set; } = string.Empty;
    }
}

