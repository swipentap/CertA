using CertA.Data;
using CertA.Models;
using CertA.Options;
using CertA.Services;
using Serilog;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.HttpOverrides;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Host.UseSerilog((ctx, lc) =>
{
    var conn = ctx.Configuration.GetConnectionString("DefaultConnection");
    lc.MinimumLevel.Information()
      .WriteTo.Console()
      .WriteTo.PostgreSQL(
          connectionString: conn!,
          tableName: "application_logs",
          needAutoCreateTable: true);
});

builder.Services.AddControllersWithViews(options =>
{
    var keycloakOn = builder.Configuration.GetValue<bool>($"{KeycloakOptions.SectionName}:Enabled");
    if (keycloakOn)
        options.Filters.Add(new Microsoft.AspNetCore.Mvc.Authorization.AuthorizeFilter());
});

// Database connection factory
builder.Services.AddSingleton<IDatabaseConnectionFactory, DatabaseConnectionFactory>();

// Custom authentication services
builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddScoped<IAuthenticationService, AuthenticationService>();

// Certificate services
builder.Services.AddScoped<ICertificateService, CertificateService>();
builder.Services.AddScoped<ICertificateAuthorityService, CertificateAuthorityService>();

// Database initialization
builder.Services.AddScoped<IDatabaseInitializationService, DatabaseInitializationService>();

// Keycloak options
builder.Services.Configure<KeycloakOptions>(builder.Configuration.GetSection(KeycloakOptions.SectionName));

// ACME options and services
builder.Services.Configure<CertA.Options.AcmeOptions>(builder.Configuration.GetSection(CertA.Options.AcmeOptions.SectionName));
builder.Services.AddHttpClient();
builder.Services.AddScoped<CertA.Services.Acme.IAcmeStorageService, CertA.Services.Acme.AcmeStorageService>();
builder.Services.AddScoped<CertA.Services.Acme.IAcmeCertificatePersistence, CertA.Services.Acme.AcmeCertificatePersistence>();
builder.Services.AddScoped<CertA.Services.Acme.IAcmeService, CertA.Services.Acme.AcmeService>();

// Forwarded headers (so behind proxy we get correct scheme/host for logout redirect, etc.)
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost;
    options.KnownNetworks.Clear();
    options.KnownProxies.Clear();
});
var keycloakEnabled = builder.Configuration.GetValue<bool>($"{KeycloakOptions.SectionName}:Enabled");

// Configure Authentication: Cookie always; OpenIdConnect (Keycloak) when enabled
var authBuilder = builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme);
authBuilder.AddCookie(options =>
{
    options.LoginPath = "/Account/Login";
    options.LogoutPath = "/Account/Logout";
    options.AccessDeniedPath = "/Account/AccessDenied";
    options.ExpireTimeSpan = TimeSpan.FromHours(12);
    options.SlidingExpiration = true;
    options.Events.OnValidatePrincipal = async context =>
    {
        await Task.CompletedTask;
    };
});

if (keycloakEnabled)
{
    // Get certa client roles from access token (Keycloak puts resource_access there; ID token often does not).
    static IEnumerable<string> GetKeycloakRolesFromAccessToken(string? accessToken, string? clientId)
    {
        var roles = new List<string>();
        if (string.IsNullOrEmpty(accessToken) || string.IsNullOrEmpty(clientId)) return roles;
        var parts = accessToken.Split('.');
        if (parts.Length != 3) return roles;
        try
        {
            var payload = parts[1];
            payload = payload.Replace('-', '+').Replace('_', '/');
            switch (payload.Length % 4) { case 2: payload += "=="; break; case 3: payload += "="; break; }
            var bytes = Convert.FromBase64String(payload);
            var json = Encoding.UTF8.GetString(bytes);
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("resource_access", out var resAccess)) return roles;
            JsonElement? clientEl = null;
            foreach (var prop in resAccess.EnumerateObject())
            {
                if (string.Equals(prop.Name, clientId, StringComparison.OrdinalIgnoreCase)) { clientEl = prop.Value; break; }
            }
            if (!clientEl.HasValue || !clientEl.Value.TryGetProperty("roles", out var rolesArr)) return roles;
            foreach (var e in rolesArr.EnumerateArray())
            {
                var r = e.GetString();
                if (!string.IsNullOrEmpty(r)) roles.Add(r);
            }
        }
        catch { /* ignore */ }
        return roles.Distinct(StringComparer.OrdinalIgnoreCase);
    }

    var keycloakAuthority = builder.Configuration.GetValue<string>($"{KeycloakOptions.SectionName}:Authority") ?? "";
    var keycloakClientId = builder.Configuration.GetValue<string>($"{KeycloakOptions.SectionName}:ClientId") ?? "";
    var keycloakClientSecret = builder.Configuration.GetValue<string>($"{KeycloakOptions.SectionName}:ClientSecret") ?? "";
    var keycloakCallbackPath = builder.Configuration.GetValue<string>($"{KeycloakOptions.SectionName}:CallbackPath") ?? "/signin-oidc";
    var requireHttpsMetadata = builder.Configuration.GetValue<bool>($"{KeycloakOptions.SectionName}:RequireHttpsMetadata");

    authBuilder.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
    {
        options.Authority = keycloakAuthority;
        options.ClientId = keycloakClientId;
        options.ClientSecret = keycloakClientSecret;
        options.CallbackPath = keycloakCallbackPath;
        options.RequireHttpsMetadata = requireHttpsMetadata;
        options.ResponseType = "code";
        options.SaveTokens = true;
        options.GetClaimsFromUserInfoEndpoint = true;
        options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.BackchannelHttpHandler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true
        };
        options.PushedAuthorizationBehavior = PushedAuthorizationBehavior.Disable;

        options.Events.OnRemoteFailure = context =>
        {
            var message = context.Failure?.Message ?? "Authentication failed.";
            context.Response.Redirect("/Account/AccessDenied?message=" + Uri.EscapeDataString(message));
            context.HandleResponse();
            return Task.CompletedTask;
        };

        options.Events.OnTokenValidated = async context =>
        {
            var userService = context.HttpContext.RequestServices.GetRequiredService<IUserService>();
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            var keycloakPrincipal = context.Principal;

            var email = keycloakPrincipal?.FindFirst(ClaimTypes.Email)?.Value
                ?? keycloakPrincipal?.FindFirst("email")?.Value
                ?? keycloakPrincipal?.FindFirst("preferred_username")?.Value;
            if (string.IsNullOrEmpty(email))
            {
                logger.LogWarning("Keycloak token has no email or preferred_username; rejecting.");
                context.Fail("No email claim from Keycloak.");
                return;
            }

            var user = await userService.GetUserByEmailAsync(email);
            if (user == null)
            {
                var name = keycloakPrincipal?.FindFirst(ClaimTypes.Name)?.Value ?? keycloakPrincipal?.FindFirst("name")?.Value ?? "";
                var givenName = keycloakPrincipal?.FindFirst(ClaimTypes.GivenName)?.Value ?? keycloakPrincipal?.FindFirst("given_name")?.Value ?? "";
                var familyName = keycloakPrincipal?.FindFirst(ClaimTypes.Surname)?.Value ?? keycloakPrincipal?.FindFirst("family_name")?.Value ?? "";
                var newUser = new ApplicationUser
                {
                    UserName = email,
                    Email = email,
                    FirstName = !string.IsNullOrEmpty(givenName) ? givenName : (name.Length > 0 ? name : null),
                    LastName = !string.IsNullOrEmpty(familyName) ? familyName : null,
                    EmailConfirmed = true,
                    IsActive = true
                };
                var created = await userService.CreateUserAsync(newUser, Convert.ToBase64String(Guid.NewGuid().ToByteArray()));
                if (!created)
                {
                    user = await userService.GetUserByEmailAsync(email);
                }
                else
                {
                    user = newUser;
                    logger.LogInformation("Auto-provisioned user from Keycloak: {Email}", email);
                }
            }

            if (user == null || !user.IsActive)
            {
                context.Fail("User not found or inactive.");
                return;
            }

            // Roles only from access token (resource_access.certa.roles). When Keycloak is on, whole site is admin-only.
            var accessToken = context.TokenEndpointResponse?.GetParameter("access_token");
            if (string.IsNullOrEmpty(accessToken) && context.Properties.Items.TryGetValue(".Token.access_token", out var stored) && stored != null)
                accessToken = stored;
            var keycloakRoles = GetKeycloakRolesFromAccessToken(accessToken, keycloakClientId).ToList();
            var hasCertaAdmin = keycloakRoles.Any(r => string.Equals(r, "admin", StringComparison.OrdinalIgnoreCase));
            if (!hasCertaAdmin)
            {
                logger.LogWarning("Keycloak user {Email} rejected: certa client role 'admin' required.", email);
                context.Fail("Access requires the certa admin role.");
                return;
            }
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Name, user.UserName ?? user.Email ?? ""),
                new Claim(ClaimTypes.Email, user.Email ?? ""),
            };
            if (!string.IsNullOrEmpty(user.FirstName))
                claims.Add(new Claim(ClaimTypes.GivenName, user.FirstName));
            if (!string.IsNullOrEmpty(user.LastName))
                claims.Add(new Claim(ClaimTypes.Surname, user.LastName));
            foreach (var role in keycloakRoles)
            {
                if (string.IsNullOrEmpty(role)) continue;
                claims.Add(new Claim(ClaimTypes.Role, role));
                // So that [Authorize(Roles = "Admin")] works when Keycloak has "admin"
                if (string.Equals(role, "admin", StringComparison.OrdinalIgnoreCase) && role != "Admin")
                    claims.Add(new Claim(ClaimTypes.Role, "Admin"));
            }
            var identity = new ClaimsIdentity(claims, "Cookies");
            context.Principal = new ClaimsPrincipal(identity);
        };
    });

    builder.Services.Configure<Microsoft.AspNetCore.Authentication.AuthenticationOptions>(options =>
    {
        options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    });
}

// Configure Data Protection (simplified - using file system for now, can be enhanced later)
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(builder.Environment.ContentRootPath, "DataProtection-Keys")));

builder.Services.AddAuthorization();

var app = builder.Build();

// Initialize database schema
using (var scope = app.Services.CreateScope())
{
    var dbInit = scope.ServiceProvider.GetRequiredService<IDatabaseInitializationService>();
    try
    {
        await dbInit.InitializeDatabaseAsync();
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Database initialization failed: {ex.Message}");
    }

    // Create default admin user if no users exist, and ensure admin@certa.local has Admin role
    var userService = scope.ServiceProvider.GetRequiredService<IUserService>();
    var existingAdmin = await userService.GetUserByEmailAsync("admin@certa.local");
    if (existingAdmin == null)
    {
        var adminUser = new ApplicationUser
        {
            UserName = "admin@certa.local",
            Email = "admin@certa.local",
            FirstName = "Admin",
            LastName = "User",
            Organization = "CertA",
            EmailConfirmed = true
        };

        var created = await userService.CreateUserAsync(adminUser, "Admin123!");
        if (created)
        {
            await userService.EnsureUserInRoleAsync(adminUser.Id, "Admin");
            Console.WriteLine("Default admin user created: admin@certa.local / Admin123!");
        }
    }
    else
    {
        await userService.EnsureUserInRoleAsync(existingAdmin.Id, "Admin");
    }
}

// Configure the HTTP request pipeline.
app.UseForwardedHeaders();
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.MapGet("/health", () => Results.Ok());

app.Run();