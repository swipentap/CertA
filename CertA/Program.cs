using CertA.Data;
using CertA.Models;
using CertA.Services;
using Serilog;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Claims;

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

builder.Services.AddControllersWithViews();

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

// Configure Cookie Authentication (replacing Identity)
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Account/Login";
        options.LogoutPath = "/Account/Logout";
        options.AccessDeniedPath = "/Account/AccessDenied";
        options.ExpireTimeSpan = TimeSpan.FromHours(12);
        options.SlidingExpiration = true;
        options.Events.OnValidatePrincipal = async context =>
        {
            // Custom validation if needed
            await Task.CompletedTask;
        };
    });

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

    // Create default admin user if no users exist
    var userService = scope.ServiceProvider.GetRequiredService<IUserService>();
    var existingUsers = await userService.GetUserByEmailAsync("admin@certa.local");
    if (existingUsers == null)
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
            Console.WriteLine("Default admin user created: admin@certa.local / Admin123!");
        }
    }
}

// Configure the HTTP request pipeline.
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

app.Run();