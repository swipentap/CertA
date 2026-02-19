using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace CertA.Tests.Acme.Fakes;

/// <summary>
/// Returns a configurable body for ACME HTTP-01 challenge URLs (/.well-known/acme-challenge/*).
/// </summary>
public sealed class ChallengeHttpHandler : HttpMessageHandler
{
    private string? _keyAuthorization;

    public void SetKeyAuthorization(string keyAuthorization) => _keyAuthorization = keyAuthorization;

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var path = request.RequestUri?.AbsolutePath ?? "";
        if (path.Contains(".well-known/acme-challenge/") && _keyAuthorization != null)
        {
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(_keyAuthorization)
            });
        }
        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
    }
}
