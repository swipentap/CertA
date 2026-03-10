using CertA.Data;
using CertA.Models;
using CertA.Options;
using CertA.Services;
using Serilog;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.EntityFrameworkCore;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using OpenIddict.Abstractions;

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
    var oauth2On = builder.Configuration.GetValue<bool>($"{OAuth2Options.SectionName}:Enabled");
    if (oauth2On)
        options.Filters.Add(new Microsoft.AspNetCore.Mvc.Authorization.AuthorizeFilter());
});
builder.Services.AddAntiforgery(options =>
{
    options.Cookie.Path = "/";
    options.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Lax;
    options.HeaderName = "X-XSRF-TOKEN";
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

// OAuth2 options
builder.Services.Configure<OAuth2Options>(builder.Configuration.GetSection(OAuth2Options.SectionName));

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
var oauth2Enabled = builder.Configuration.GetValue<bool>($"{OAuth2Options.SectionName}:Enabled");
var oauth2UseEmbedded = builder.Configuration.GetValue<bool>($"{OAuth2Options.SectionName}:UseEmbedded");

if (oauth2UseEmbedded)
{
    var conn = builder.Configuration.GetConnectionString("DefaultConnection");
    builder.Services.AddDbContext<OpenIddictDbContext>(options =>
    {
        options.UseNpgsql(conn);
        options.UseOpenIddict();
    });
    builder.Services.AddOpenIddict()
        .AddCore(options =>
        {
            options.UseEntityFrameworkCore()
                .UseDbContext<OpenIddictDbContext>();
        })
        .AddServer(options =>
        {
            options.SetAuthorizationEndpointUris("/connect/authorize")
                .SetTokenEndpointUris("/connect/token");
            options.AllowAuthorizationCodeFlow().AllowRefreshTokenFlow();
            options.AddDevelopmentEncryptionCertificate();
            options.AddDevelopmentSigningCertificate();
            options.UseAspNetCore()
                .EnableAuthorizationEndpointPassthrough()
                .EnableTokenEndpointPassthrough();
        });
}

// Configure Authentication: Cookie always; OpenIdConnect (OAuth2) when enabled
var authBuilder = builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme);
authBuilder.AddCookie(options =>
{
    options.LoginPath = "/login";
    options.LogoutPath = "/Account/Logout";
    options.AccessDeniedPath = "/Account/AccessDenied";
    options.ExpireTimeSpan = TimeSpan.FromHours(12);
    options.SlidingExpiration = true;
    options.Cookie.Path = "/";
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.Cookie.IsEssential = true;
    options.Events.OnValidatePrincipal = async context =>
    {
        await Task.CompletedTask;
    };
});

if (oauth2Enabled)
{
    // Get certa client roles from access token (OAuth2 IdP puts resource_access there; ID token often does not).
    static IEnumerable<string> GetOAuth2RolesFromAccessToken(string? accessToken, string? clientId)
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

    var oauth2Authority = builder.Configuration.GetValue<string>($"{OAuth2Options.SectionName}:Authority")?.TrimEnd('/') ?? "";
    if (oauth2UseEmbedded && string.IsNullOrEmpty(oauth2Authority))
        oauth2Authority = "https://localhost:8443";
    var oauth2AuthorityInternal = builder.Configuration.GetValue<string>($"{OAuth2Options.SectionName}:AuthorityInternal")?.TrimEnd('/');
    var oauth2ClientId = builder.Configuration.GetValue<string>($"{OAuth2Options.SectionName}:ClientId") ?? "";
    var oauth2ClientSecret = builder.Configuration.GetValue<string>($"{OAuth2Options.SectionName}:ClientSecret") ?? "";
    if (oauth2UseEmbedded && string.IsNullOrEmpty(oauth2ClientSecret))
        oauth2ClientSecret = "certa-embedded-dev-secret";
    var oauth2CallbackPath = builder.Configuration.GetValue<string>($"{OAuth2Options.SectionName}:CallbackPath") ?? "/signin-oidc";
    var requireHttpsMetadata = builder.Configuration.GetValue<bool>($"{OAuth2Options.SectionName}:RequireHttpsMetadata");

    authBuilder.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
    {
        options.Authority = oauth2Authority;
        if (!string.IsNullOrEmpty(oauth2AuthorityInternal))
        {
            options.MetadataAddress = oauth2AuthorityInternal + "/.well-known/openid-configuration";
            options.TokenValidationParameters.ValidIssuers = new[] { oauth2Authority.TrimEnd('/'), oauth2AuthorityInternal.TrimEnd('/') };
        }
        options.ClientId = oauth2ClientId;
        options.ClientSecret = oauth2ClientSecret;
        options.CallbackPath = oauth2CallbackPath;
        options.RequireHttpsMetadata = requireHttpsMetadata;
        options.ResponseType = "code";
        options.SaveTokens = true;
        options.GetClaimsFromUserInfoEndpoint = oauth2UseEmbedded;
        options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.BackchannelHttpHandler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true
        };
        options.PushedAuthorizationBehavior = PushedAuthorizationBehavior.Disable;

        if (!string.IsNullOrEmpty(oauth2AuthorityInternal) && !string.IsNullOrEmpty(oauth2Authority))
        {
            var authorityForRedirectBase = new Uri(oauth2Authority.TrimEnd('/')).GetLeftPart(UriPartial.Authority);
            var internalAuthority = oauth2AuthorityInternal.TrimEnd('/');
            options.Events.OnRedirectToIdentityProvider = context =>
            {
                var addr = context.ProtocolMessage.IssuerAddress;
                if (!string.IsNullOrEmpty(addr) && addr.StartsWith(internalAuthority, StringComparison.OrdinalIgnoreCase))
                {
                    var pathAndQuery = new Uri(addr).PathAndQuery;
                    context.ProtocolMessage.IssuerAddress = authorityForRedirectBase + pathAndQuery;
                }
                return Task.CompletedTask;
            };
        }

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
            var oidcPrincipal = context.Principal;

            var email = oidcPrincipal?.FindFirst(ClaimTypes.Email)?.Value
                ?? oidcPrincipal?.FindFirst("email")?.Value
                ?? oidcPrincipal?.FindFirst("preferred_username")?.Value;
            var sub = oidcPrincipal?.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? oidcPrincipal?.FindFirst("sub")?.Value;
            if (string.IsNullOrEmpty(email) && string.IsNullOrEmpty(sub))
            {
                logger.LogWarning("OAuth2 token has no email/sub; rejecting.");
                context.Fail("No email/sub from OAuth2 provider.");
                return;
            }

            var user = !string.IsNullOrEmpty(sub) ? await userService.GetUserByIdAsync(sub) : null
                ?? (email != null ? await userService.GetUserByEmailAsync(email) : null);
            if (user == null && !oauth2UseEmbedded)
            {
                var name = oidcPrincipal?.FindFirst(ClaimTypes.Name)?.Value ?? oidcPrincipal?.FindFirst("name")?.Value ?? "";
                var givenName = oidcPrincipal?.FindFirst(ClaimTypes.GivenName)?.Value ?? oidcPrincipal?.FindFirst("given_name")?.Value ?? "";
                var familyName = oidcPrincipal?.FindFirst(ClaimTypes.Surname)?.Value ?? oidcPrincipal?.FindFirst("family_name")?.Value ?? "";
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
                    user = await userService.GetUserByEmailAsync(email!);
                else
                {
                    user = newUser;
                    logger.LogInformation("Auto-provisioned user from OAuth2: {Email}", email);
                }
            }

            if (user == null || !user.IsActive)
            {
                context.Fail("User not found or inactive.");
                return;
            }

            List<string> oauth2Roles;
            if (oauth2UseEmbedded)
            {
                oauth2Roles = oidcPrincipal?.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList()
                    ?? oidcPrincipal?.FindAll("role").Select(c => c.Value).ToList()
                    ?? new List<string>();
            }
            else
            {
                var accessToken = context.TokenEndpointResponse?.GetParameter("access_token");
                if (string.IsNullOrEmpty(accessToken) && context.Properties.Items.TryGetValue(".Token.access_token", out var stored) && stored != null)
                    accessToken = stored;
                oauth2Roles = GetOAuth2RolesFromAccessToken(accessToken, oauth2ClientId).ToList();
            }
            var hasAdmin = oauth2Roles.Any(r => string.Equals(r, "admin", StringComparison.OrdinalIgnoreCase) || string.Equals(r, "Admin", StringComparison.OrdinalIgnoreCase));
            if (!hasAdmin)
            {
                logger.LogWarning("OAuth2 user {Email} rejected: admin role required.", user.Email);
                context.Fail("Access requires the admin role.");
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
            foreach (var role in oauth2Roles)
            {
                if (string.IsNullOrEmpty(role)) continue;
                claims.Add(new Claim(ClaimTypes.Role, role));
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

    if (oauth2UseEmbedded)
    {
        var openIdCtx = scope.ServiceProvider.GetRequiredService<OpenIddictDbContext>();
        await openIdCtx.Database.MigrateAsync();
        var scopeManager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
        foreach (var scopeName in new[] { "openid", "profile", "email", "roles" })
        {
            if (await scopeManager.FindByNameAsync(scopeName) is null)
            {
                await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
                {
                    Name = scopeName,
                    DisplayName = scopeName
                });
            }
        }
        var appManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var clientId = builder.Configuration.GetValue<string>($"{OAuth2Options.SectionName}:ClientId") ?? "certa";
        var clientSecret = builder.Configuration.GetValue<string>($"{OAuth2Options.SectionName}:ClientSecret");
        if (string.IsNullOrEmpty(clientSecret))
            clientSecret = "certa-embedded-dev-secret";
        var authority = builder.Configuration.GetValue<string>($"{OAuth2Options.SectionName}:Authority")?.TrimEnd('/') ?? "";
        var callbackPath = builder.Configuration.GetValue<string>($"{OAuth2Options.SectionName}:CallbackPath") ?? "/signin-oidc";
        var redirectUri = string.IsNullOrEmpty(authority) ? "https://localhost:8443/signin-oidc" : $"{authority}{callbackPath}";
        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            ClientType = OpenIddictConstants.ClientTypes.Confidential,
            ClientSecret = string.IsNullOrEmpty(clientSecret) ? null : clientSecret,
            DisplayName = "CertA",
            RedirectUris = { new Uri(redirectUri) },
            PostLogoutRedirectUris = { new Uri(authority.Length > 0 ? authority : "https://localhost:8443") },
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                OpenIddictConstants.Permissions.ResponseTypes.Code,
                OpenIddictConstants.Permissions.Prefixes.Scope + "openid",
                OpenIddictConstants.Permissions.Prefixes.Scope + "profile",
                OpenIddictConstants.Permissions.Prefixes.Scope + "email",
                OpenIddictConstants.Permissions.Prefixes.Scope + "roles"
            }
        };
        var existingApp = await appManager.FindByClientIdAsync("certa");
        if (existingApp is null)
        {
            await appManager.CreateAsync(descriptor);
        }
        else
        {
            await appManager.PopulateAsync(existingApp, descriptor);
            await appManager.UpdateAsync(existingApp);
        }
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

    if (oauth2UseEmbedded)
    {
        var noAdmin = await userService.GetUserByEmailAsync("certa_noadmin@certa.local");
        if (noAdmin == null)
        {
            var noAdminUser = new ApplicationUser
            {
                UserName = "certa_noadmin@certa.local",
                Email = "certa_noadmin@certa.local",
                FirstName = "NoAdmin",
                LastName = "User",
                EmailConfirmed = true,
                IsActive = true
            };
            if (await userService.CreateUserAsync(noAdminUser, "noadmin123"))
                Console.WriteLine("Embedded OAuth2 no-admin test user created: certa_noadmin@certa.local / noadmin123");
        }
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
app.UseDefaultFiles();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
// Serve SPA for "/" so authenticated users land on Vue app, not Razor dashboard
app.MapGet("/", (IWebHostEnvironment env) =>
{
    var path = Path.Combine(env.WebRootPath ?? "wwwroot", "index.html");
    return System.IO.File.Exists(path) ? Results.File(path, "text/html") : Results.NotFound();
});
app.MapControllerRoute(
    name: "default",
    pattern: "{controller}/{action}/{id?}");
app.MapGet("/health", () => Results.Ok());
app.MapFallbackToFile("index.html");

app.Run();