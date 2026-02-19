namespace CertA.Options;

public class KeycloakOptions
{
    public const string SectionName = "Authentication:Keycloak";

    public bool Enabled { get; set; }
    public string Authority { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;
    public string CallbackPath { get; set; } = "/signin-oidc";
    public bool RequireHttpsMetadata { get; set; } = true;
}
