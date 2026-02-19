namespace CertA.Options;

public class AcmeOptions
{
    public const string SectionName = "Acme";

    public bool Enabled { get; set; } = true;

    public string DirectoryBaseUrl { get; set; } = string.Empty;

    public string SystemUserId { get; set; } = string.Empty;

    public int HttpChallengeTimeoutSeconds { get; set; } = 30;
}
