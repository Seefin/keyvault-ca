using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace KeyVaultCa.Core
{
    public interface IKeyVaultCertificateProvider
    {
        Task CreateCACertificateAsync(CertificateConfiguration config);

        Task<IList<X509Certificate2>> GetPublicCertificatesByName(IEnumerable<string> certNames);

        Task<X509Certificate2> GetCertificateAsync(string issuerCertificateName);

        Task<X509Certificate2> SignRequestAsync(CertificateConfiguration config);
    }
}