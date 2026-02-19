namespace CertA.Models.Acme;

public class AcmeAccount
{
    public int Id { get; set; }
    public required string AccountId { get; set; }
    public required string KeyJwk { get; set; }
    public required string KeyThumbprint { get; set; }
    public required string Status { get; set; }
    public DateTime CreatedAt { get; set; }
}
