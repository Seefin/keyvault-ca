using System;

namespace KeyVaultCa.Core
{
    public class CertificateConfiguration
    {
        public bool IsRootCA {get; set; } = false;

        public bool IsIntermediateCA {get; set; } = false;

        public string IssuerCertificateName { get; set; }

        public string Subject { get; set; }

        public int PathLength { get; set; }

        public int ValidityMonths { get; set; }

        public int ValidityDays { get; set; }

        public int KeySize { get; set; } = 4096;

        public byte[] Csr { get; set; }
    }
}