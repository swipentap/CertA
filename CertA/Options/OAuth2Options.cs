namespace CertA.Options;

public class OAuth2Options
{
    public const string SectionName = "Authentication:OAuth2";

    public bool Enabled { get; set; }
    /// <summary>When true, use embedded OpenIddict instead of external IdP (e.g. Keycloak).</summary>
    public bool UseEmbedded { get; set; }
    /// <summary>Authority URL. For external: IdP base URL. For embedded: app base URL (e.g. https://localhost:8443).</summary>
    public string Authority { get; set; } = string.Empty;
    /// <summary>When set, used for metadata discovery (e.g. https://localhost:8081 in Docker). Lets app reach itself when Authority is external URL.</summary>
    public string? AuthorityInternal { get; set; }
    public string ClientId { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;
    public string CallbackPath { get; set; } = "/signin-oidc";
    public bool RequireHttpsMetadata { get; set; } = true;
}
