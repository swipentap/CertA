using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace CertA.Services.Acme;

/// <summary>
/// Handles JWS (JSON Web Signature) parsing and verification per RFC 8555 §6.2.
/// </summary>
public static class AcmeJwsHandler
{
    public static byte[] Base64UrlDecode(string input)
    {
        var s = input.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4)
        {
            case 2: s += "=="; break;
            case 3: s += "="; break;
        }
        return Convert.FromBase64String(s);
    }

    public static string Base64UrlEncode(byte[] data)
    {
        return Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    public static async Task<AcmeJwsPayload> ParseAndVerifyAsync(Stream body, string requestedUrl, Func<string, string, Task<(RSA? Key, string? AccountId)>> getAccountKeyAsync, Func<string, Task<bool>> consumeNonceAsync)
    {
        using var reader = new StreamReader(body);
        var json = await reader.ReadToEndAsync();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        if (!root.TryGetProperty("protected", out var protectedB64))
            throw new AcmeException("missing protected", "malformed");
        if (!root.TryGetProperty("payload", out var payloadB64))
            throw new AcmeException("missing payload", "malformed");
        if (!root.TryGetProperty("signature", out var sigB64))
            throw new AcmeException("missing signature", "malformed");

        var protectedB64Str = protectedB64.GetString()!;
        var payloadB64Str = payloadB64.GetString() ?? "";
        var protectedJson = Encoding.UTF8.GetString(Base64UrlDecode(protectedB64Str));
        var signature = Base64UrlDecode(sigB64.GetString()!);
        var signedData = Encoding.UTF8.GetBytes(protectedB64Str + "." + payloadB64Str);

        using var headerDoc = JsonDocument.Parse(protectedJson);
        var header = headerDoc.RootElement;
        var alg = header.TryGetProperty("alg", out var a) ? a.GetString() : null;
        var nonce = header.TryGetProperty("nonce", out var n) ? n.GetString() : null;
        var url = header.TryGetProperty("url", out var u) ? u.GetString() : null;
        var jwk = header.TryGetProperty("jwk", out var j) ? j : default;
        var kid = header.TryGetProperty("kid", out var k) ? k.GetString() : null;

        if (string.IsNullOrEmpty(alg) || string.IsNullOrEmpty(nonce) || string.IsNullOrEmpty(url))
            throw new AcmeException("invalid protected header", "malformed");
        if (url != requestedUrl)
            throw new AcmeException("url mismatch", "unauthorized");

        var nonceOk = await consumeNonceAsync(nonce);
        if (!nonceOk)
            throw new AcmeException("invalid nonce", "badNonce");

        RSA? key = null;
        string? accountId = null;
        if (jwk.ValueKind == JsonValueKind.Object)
        {
            var jwkJson = jwk.GetRawText();
            key = JwkToRsa(jwkJson);
        }
        else if (!string.IsNullOrEmpty(kid))
        {
            var (resolvedKey, resolvedAccountId) = await getAccountKeyAsync(kid, "");
            key = resolvedKey;
            accountId = resolvedAccountId;
        }

        if (key == null)
            throw new AcmeException("could not resolve account key", "unauthorized");

        using (key)
        {
            var algName = alg.ToUpperInvariant();
            var hashAlg = algName switch
            {
                "RS256" => HashAlgorithmName.SHA256,
                "RS384" => HashAlgorithmName.SHA384,
                "RS512" => HashAlgorithmName.SHA512,
                _ => throw new AcmeException("unsupported alg " + alg, "badSignatureAlgorithm")
            };

            if (!key.VerifyData(signedData, signature, hashAlg, RSASignaturePadding.Pkcs1))
                throw new AcmeException("invalid signature", "unauthorized");
        }

        string? payloadJson = null;
        if (!string.IsNullOrEmpty(payloadB64Str))
        {
            payloadJson = Encoding.UTF8.GetString(Base64UrlDecode(payloadB64Str));
        }

        return new AcmeJwsPayload(AccountId: accountId, PayloadJson: payloadJson, ProtectedHeaderJson: protectedJson);
    }

    public static RSA JwkToRsa(string jwkJson)
    {
        using var doc = JsonDocument.Parse(jwkJson);
        var root = doc.RootElement;
        var kty = root.TryGetProperty("kty", out var k) ? k.GetString() : null;
        if (kty != "RSA")
            throw new AcmeException("only RSA keys supported", "badPublicKey");

        var n = root.TryGetProperty("n", out var nEl) ? Base64UrlDecode(nEl.GetString()!) : null;
        var e = root.TryGetProperty("e", out var eEl) ? Base64UrlDecode(eEl.GetString()!) : null;
        if (n == null || e == null)
            throw new AcmeException("missing n or e in JWK", "badPublicKey");

        var rsa = RSA.Create();
        rsa.ImportParameters(new RSAParameters { Modulus = n, Exponent = e });
        return rsa;
    }

    public static byte[] ComputeJwkThumbprint(string jwkJson)
    {
        using var doc = JsonDocument.Parse(jwkJson);
        var root = doc.RootElement;
        var required = new[] { "e", "kty", "n" };
        var ordered = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (var key in required)
        {
            if (root.TryGetProperty(key, out var v))
                ordered[key] = v.GetString() ?? "";
        }
        var canon = JsonSerializer.Serialize(ordered);
        using var sha = SHA256.Create();
        return sha.ComputeHash(Encoding.UTF8.GetBytes(canon));
    }
}

public record AcmeJwsPayload(string? AccountId, string? PayloadJson, string? ProtectedHeaderJson);

public class AcmeException : Exception
{
    public string Type { get; }

    public AcmeException(string message, string type) : base(message)
    {
        Type = type;
    }
}
