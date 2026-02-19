namespace CertA.Models.Acme;

public class AcmeChallenge
{
    public int Id { get; set; }
    public required string ChallengeId { get; set; }
    public required string AuthId { get; set; }
    public required string Type { get; set; }
    public required string Token { get; set; }
    public required string KeyAuthorization { get; set; }
    public required string Status { get; set; }
    public DateTime? ValidatedAt { get; set; }
    public DateTime CreatedAt { get; set; }
}
