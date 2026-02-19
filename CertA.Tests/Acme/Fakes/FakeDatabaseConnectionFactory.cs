using CertA.Data;
using System.Data;

namespace CertA.Tests.Acme.Fakes;

public sealed class FakeDatabaseConnectionFactory : IDatabaseConnectionFactory
{
    public Task<IDbConnection> CreateConnectionAsync() =>
        Task.FromResult<IDbConnection>(new FakeDbConnection());
}
