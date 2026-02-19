using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CertA.Services.Acme;

namespace CertA.Tests.Acme.TestHelpers;

/// <summary>
/// Builds RFC 8555 JWS bodies for unit tests (signed with RSA).
/// </summary>
public static class JwsBuilder
{
    public static string BuildJws(RSA key, string url, string? payloadJson, string? nonce, string? kid = null, string? jwkJson = null)
    {
        var alg = "RS256";
        var payloadB64 = string.IsNullOrEmpty(payloadJson)
            ? ""
            : AcmeJwsHandler.Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson ?? "{}"));

        using var header = new MemoryStream();
        using (var w = new Utf8JsonWriter(header, new JsonWriterOptions { Indented = false }))
        {
            w.WriteStartObject();
            w.WriteString("alg", alg);
            if (!string.IsNullOrEmpty(nonce)) w.WriteString("nonce", nonce);
            w.WriteString("url", url);
            if (!string.IsNullOrEmpty(kid)) w.WriteString("kid", kid);
            if (!string.IsNullOrEmpty(jwkJson))
            {
                w.WritePropertyName("jwk");
                using var jwkDoc = JsonDocument.Parse(jwkJson);
                jwkDoc.RootElement.WriteTo(w);
            }
            w.WriteEndObject();
        }
        var protectedB64 = AcmeJwsHandler.Base64UrlEncode(header.ToArray());
        var signedData = Encoding.UTF8.GetBytes(protectedB64 + "." + payloadB64);
        var signature = key.SignData(signedData, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var sigB64 = AcmeJwsHandler.Base64UrlEncode(signature);

        using var body = new MemoryStream();
        using (var w = new Utf8JsonWriter(body, new JsonWriterOptions { Indented = false }))
        {
            w.WriteStartObject();
            w.WriteString("protected", protectedB64);
            w.WriteString("payload", payloadB64);
            w.WriteString("signature", sigB64);
            w.WriteEndObject();
        }
        return Encoding.UTF8.GetString(body.ToArray());
    }

    public static string RsaJwkToJson(RSA key)
    {
        var p = key.ExportParameters(false);
        var n = AcmeJwsHandler.Base64UrlEncode(p.Modulus!);
        var e = AcmeJwsHandler.Base64UrlEncode(p.Exponent!);
        return $$"""{"kty":"RSA","n":"{{n}}","e":"{{e}}"}""";
    }
}
