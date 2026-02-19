using CertA.Services.Acme;
using NUnit.Framework;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace CertA.Tests.Acme;

[TestFixture]
public class AcmeJwsHandlerTests
{
    [Test]
    public void Base64UrlDecode_RoundTrip_Succeeds()
    {
        var original = "hello+world/foo==";
        var bytes = Encoding.UTF8.GetBytes(original);
        var encoded = AcmeJwsHandler.Base64UrlEncode(bytes);
        var decoded = AcmeJwsHandler.Base64UrlDecode(encoded);
        Assert.That(decoded, Is.EqualTo(bytes));
    }

    [Test]
    public void Base64UrlEncode_ProducesUrlSafeOutput()
    {
        var bytes = new byte[] { 0x00, 0xff, 0xfe };
        var encoded = AcmeJwsHandler.Base64UrlEncode(bytes);
        Assert.That(encoded, Does.Not.Contain("+"));
        Assert.That(encoded, Does.Not.Contain("/"));
    }

    [Test]
    public void ComputeJwkThumbprint_RsaKey_Returns32Bytes()
    {
        var jwk = """{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB"}""";
        var thumbprint = AcmeJwsHandler.ComputeJwkThumbprint(jwk);
        Assert.That(thumbprint, Has.Length.EqualTo(32));
    }

    [Test]
    public void JwkToRsa_ValidRsaJwk_ReturnsRsaKey()
    {
        using var rsa = RSA.Create(2048);
        var exported = rsa.ExportParameters(false);
        var n = AcmeJwsHandler.Base64UrlEncode(exported.Modulus!);
        var e = AcmeJwsHandler.Base64UrlEncode(exported.Exponent!);
        var jwk = $$"""{"kty":"RSA","n":"{{n}}","e":"{{e}}"}""";

        using var imported = AcmeJwsHandler.JwkToRsa(jwk);
        Assert.That(imported, Is.Not.Null);
        Assert.That(imported!.KeySize, Is.GreaterThanOrEqualTo(2048));
    }

    [Test]
    public void JwkToRsa_InvalidKty_Throws()
    {
        var jwk = """{"kty":"EC","crv":"P-256","x":"xxx","y":"yyy"}""";
        Assert.Throws<AcmeException>(() => AcmeJwsHandler.JwkToRsa(jwk));
    }
}
