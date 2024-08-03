namespace KeyVaultCa.Core
{
    public class CertificateConfiguration
    {
        public string IssuerCertificateName { get; set; }

        public string Subject { get; set; }

        public int PathLength { get; set; }

        public int ValidityMonths { get; set; }

        public int KeySize { get; set; } = 4096;
    }
}