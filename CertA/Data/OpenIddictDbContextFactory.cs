using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;

namespace CertA.Data;

public class OpenIddictDbContextFactory : IDesignTimeDbContextFactory<OpenIddictDbContext>
{
    public OpenIddictDbContext CreateDbContext(string[] args)
    {
        var config = new ConfigurationBuilder()
            .SetBasePath(Directory.GetCurrentDirectory())
            .AddJsonFile("appsettings.json", optional: true)
            .AddEnvironmentVariables()
            .Build();
        var conn = config.GetConnectionString("DefaultConnection") ?? "Host=localhost;Port=5433;Database=certa;Username=certa;Password=certa123";
        var options = new DbContextOptionsBuilder<OpenIddictDbContext>()
            .UseNpgsql(conn)
            .Options;
        return new OpenIddictDbContext(options);
    }
}
