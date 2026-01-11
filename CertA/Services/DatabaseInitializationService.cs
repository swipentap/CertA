using CertA.Data;
using System.Data;
using System.IO;
using Dapper;

namespace CertA.Services
{
    public interface IDatabaseInitializationService
    {
        Task InitializeDatabaseAsync();
    }

    public class DatabaseInitializationService : IDatabaseInitializationService
    {
        private readonly IDatabaseConnectionFactory _connectionFactory;
        private readonly ILogger<DatabaseInitializationService> _logger;

        public DatabaseInitializationService(IDatabaseConnectionFactory connectionFactory, ILogger<DatabaseInitializationService> logger)
        {
            _connectionFactory = connectionFactory;
            _logger = logger;
        }

        public async Task InitializeDatabaseAsync()
        {
            try
            {
                var schemaPath = Path.Combine(AppContext.BaseDirectory, "Scripts", "schema.sql");
                if (!File.Exists(schemaPath))
                {
                    _logger.LogWarning("Schema file not found at {Path}, skipping database initialization", schemaPath);
                    return;
                }

                var schemaSql = await File.ReadAllTextAsync(schemaPath);
                
                using var connection = await _connectionFactory.CreateConnectionAsync();
                connection.Open();
                
                // Execute schema SQL
                await connection.ExecuteAsync(schemaSql);
                
                _logger.LogInformation("Database schema initialized successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to initialize database schema");
                throw;
            }
        }
    }
}