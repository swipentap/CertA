namespace CertA.Models.Acme;

public class AcmeOrder
{
    public int Id { get; set; }
    public required string OrderId { get; set; }
    public required string AccountId { get; set; }
    public required string Identifiers { get; set; }
    public required string Status { get; set; }
    public DateTime Expires { get; set; }
    public int? CertificateId { get; set; }
    public string? CertificatePem { get; set; }
    public DateTime CreatedAt { get; set; }
}
