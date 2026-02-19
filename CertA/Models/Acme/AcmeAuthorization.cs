namespace CertA.Models.Acme;

public class AcmeAuthorization
{
    public int Id { get; set; }
    public required string AuthId { get; set; }
    public required string OrderId { get; set; }
    public required string IdentifierType { get; set; }
    public required string IdentifierValue { get; set; }
    public required string Status { get; set; }
    public DateTime Expires { get; set; }
    public DateTime CreatedAt { get; set; }
}
