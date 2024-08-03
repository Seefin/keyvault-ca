// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Pkcs;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace KeyVaultCa.Core
{
    public class KeyVaultCertificateProvider : IKeyVaultCertificateProvider
    {
        private readonly KeyVaultServiceClient _keyVaultServiceClient;
        private readonly ILogger _logger;

        public KeyVaultCertificateProvider(KeyVaultServiceClient keyVaultServiceClient, ILogger<KeyVaultCertificateProvider> logger)
        {
            _keyVaultServiceClient = keyVaultServiceClient;
            _logger = logger;
        }

        public async Task CreateCACertificateAsync(CertificateConfiguration config)
        {
            var certVersions = await _keyVaultServiceClient.GetCertificateVersionsAsync(config.IssuerCertificateName).ConfigureAwait(false);

            if (certVersions != 0)
            {
                _logger.LogInformation("A certificate with the specified issuer name {name} already exists.", config.IssuerCertificateName);
            }

            else
            {
                _logger.LogInformation("No existing certificate found, starting to create a new one.");
                var notBefore = DateTime.UtcNow.AddDays(-1);
                await _keyVaultServiceClient.CreateCACertificateAsync(
                        config.IssuerCertificateName,
                        config.Subject,
                        notBefore,
                        notBefore.AddMonths(config.ValidityMonths),
                        config.KeySize,
                        256,
                        config.PathLength);
                _logger.LogInformation("A new certificate with issuer name {name} and path length {path} was created succsessfully.", config.IssuerCertificateName, config.PathLength);
            }
        }

        public async Task<X509Certificate2> GetCertificateAsync(string issuerCertificateName)
        {
            var certBundle = await _keyVaultServiceClient.GetCertificateAsync(issuerCertificateName).ConfigureAwait(false);
            return new X509Certificate2(certBundle.Value.Cer);
        }

        public async Task<IList<X509Certificate2>> GetPublicCertificatesByName(IEnumerable<string> certNames)
        {
            var certs = new List<X509Certificate2>();

            foreach (var issuerName in certNames)
            {
                _logger.LogDebug("Call GetPublicCertificatesByName method with following certificate name: {name}.", issuerName);
                var cert = await GetCertificateAsync(issuerName).ConfigureAwait(false);

                if (cert != null)
                {
                    certs.Add(cert);
                }
            }

            return certs;
        }

        /// <summary>
        /// Creates a KeyVault signed certficate from signing request.
        /// </summary>
        public async Task<X509Certificate2> SignRequestAsync(CertificateConfiguration config)
        {
            _logger.LogInformation("Preparing certificate request with issuer name {name}, {days} days validity period and 'is a CA certificate' flag set to {flag}.", config.IssuerCertificateName, config.ValidityDays, config.IsIntermediateCA || config.IsRootCA);

            var pkcs10CertificationRequest = new Pkcs10CertificationRequest(config.Csr);

            if (!pkcs10CertificationRequest.Verify())
            {
                _logger.LogError("CSR signature invalid.");
                throw new ArgumentException("CSR signature invalid.");
            }

            var info = pkcs10CertificationRequest.GetCertificationRequestInfo();
            var notBefore = DateTime.UtcNow.AddDays(-1);

            var certBundle = await _keyVaultServiceClient.GetCertificateAsync(config.IssuerCertificateName).ConfigureAwait(false);

            var signingCert = new X509Certificate2(certBundle.Value.Cer);
            var publicKey = KeyVaultCertFactory.GetRSAPublicKey(info.SubjectPublicKeyInfo);

            return await KeyVaultCertFactory.CreateSignedCertificate(
                info.Subject.ToString(),
                2048,
                notBefore,
                notBefore.AddDays(config.ValidityDays),
                256,
                signingCert,
                publicKey,
                new KeyVaultSignatureGenerator(_keyVaultServiceClient.Credential, certBundle.Value.KeyId, signingCert),
                config.IsIntermediateCA || config.IsRootCA
                );
        }
    }
}