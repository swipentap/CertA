using CertA.Models;
using CertA.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using System.Security.Claims;

namespace CertA.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly ICertificateService _certificateService;
        private readonly ICertificateAuthorityService _caService;

        public HomeController(
            ILogger<HomeController> logger,
            ICertificateService certificateService,
            ICertificateAuthorityService caService)
        {
            _logger = logger;
            _certificateService = certificateService;
            _caService = caService;
        }

        public IActionResult Index()
        {
            return Redirect("/");
        }

        public IActionResult Privacy()
        {
            return Redirect("/privacy");
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return Redirect("/");
        }
    }
}