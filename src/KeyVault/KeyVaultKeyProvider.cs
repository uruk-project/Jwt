// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.WebKey;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using KVECParameters = Microsoft.Azure.KeyVault.WebKey.ECParameters;
#if !NETFRAMEWORK
using SscECParameters = System.Security.Cryptography.ECParameters;
#endif

namespace JsonWebToken.KeyVault
{
    public sealed class KeyVaultKeyProvider : IKeyProvider
    {
        private readonly IKeyVaultClient _client;
        private readonly string _vaultBaseUrl;

        public int MaxResults { get; set; } = 10;

        public KeyVaultKeyProvider(string vaulBaseUrl, IKeyVaultClient client)
        {
            _vaultBaseUrl = vaulBaseUrl ?? throw new ArgumentNullException(nameof(vaulBaseUrl));
            _client = client;
        }

        public KeyVaultKeyProvider(string vaulBaseUrl, string clientId, X509Certificate2 certificate)
        {
            _vaultBaseUrl = vaulBaseUrl ?? throw new ArgumentNullException(nameof(vaulBaseUrl));
            _client = new KeyVaultClient((authority, resource, scope) => GetTokenFromClientCertificate(authority, resource, clientId, certificate));
        }

        public KeyVaultKeyProvider(string vaulBaseUrl, string clientId, string clientSecret)
        {
            _vaultBaseUrl = vaulBaseUrl ?? throw new ArgumentNullException(nameof(vaulBaseUrl));
            _client = new KeyVaultClient((authority, resource, scope) => GetTokenFromClientSecret(authority, resource, clientId, clientSecret));
        }

        public Jwk[] GetKeys(JwtHeader header)
        {
            return GetKeysAsync().GetAwaiter().GetResult();
        }

        private async Task<Jwk[]> GetKeysAsync()
        {
            var keys = new List<Jwk>();
            var keyIdentifiers = await _client.GetKeysAsync(_vaultBaseUrl, MaxResults);
            foreach (var keyIdentifier in keyIdentifiers)
            {
                var kvKey = await _client.GetKeyAsync(keyIdentifier.Identifier.Identifier);
                Jwk? key = kvKey.Key.Kty switch
                {
                    JsonWebKeyType.Octet => new SymmetricJwk(kvKey.Key.K),
                    JsonWebKeyType.Rsa => new RsaJwk(kvKey.Key.ToRSAParameters()),
                    JsonWebKeyType.RsaHsm => new RsaJwk(kvKey.Key.ToRSAParameters()),
#if !NETFRAMEWORK
                    JsonWebKeyType.EllipticCurve => ECJwk.FromParameters(ConvertToECParameters(kvKey.Key.ToEcParameters())),
                    JsonWebKeyType.EllipticCurveHsm => ECJwk.FromParameters(ConvertToECParameters(kvKey.Key.ToEcParameters())),
#endif
                    _ => null
                };

                if (!(key is null))
                {
                    key.Kid = kvKey.Key.Kid;
                    if (kvKey.Key.KeyOps != null)
                    {
                        for (int i = 0; i < kvKey.Key.KeyOps.Count; i++)
                        {
                            key.KeyOps.Add(kvKey.Key.KeyOps[i]);
                        }
                    }

                    keys.Add(key);
                }
            }

            return keys.ToArray();
        }

#if !NETFRAMEWORK
        private static SscECParameters ConvertToECParameters(KVECParameters inputParameters)
        {
            var curve = inputParameters.Curve switch
            {
                "P-256" => ECCurve.NamedCurves.nistP256,
                "P-384" => ECCurve.NamedCurves.nistP384,
                "P521" => ECCurve.NamedCurves.nistP521,
                _ => throw new NotSupportedException(),
            };
            return new SscECParameters
            {
                Curve = curve,
                D = inputParameters.D,
                Q = new ECPoint
                {
                    X = inputParameters.X,
                    Y = inputParameters.Y
                }
            };
        }
#endif

        private static async Task<string> GetTokenFromClientCertificate(string authority, string resource, string clientId, X509Certificate2 certificate)
        {
            var authContext = new AuthenticationContext(authority);
            var result = await authContext.AcquireTokenAsync(resource, new ClientAssertionCertificate(clientId, certificate));
            return result.AccessToken;
        }

        private static async Task<string> GetTokenFromClientSecret(string authority, string resource, string clientId, string clientSecret)
        {
            var authContext = new AuthenticationContext(authority);
            var result = await authContext.AcquireTokenAsync(resource, new ClientCredential(clientId, clientSecret));
            return result.AccessToken;
        }
    }
}