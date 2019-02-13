// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.WebKey;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using KVECParameters = Microsoft.Azure.KeyVault.WebKey.ECParameters;
using SscECParameters = System.Security.Cryptography.ECParameters;

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

        public IReadOnlyList<Jwk> GetKeys(JwtHeader header)
        {
            return GetKeysAsync(header).GetAwaiter().GetResult();
        }

        private async Task<IReadOnlyList<Jwk>> GetKeysAsync(JwtHeader header)
        {
            var keys = new List<Jwk>();
            var keyIdentifiers = await _client.GetKeysAsync(_vaultBaseUrl, MaxResults);
            foreach (var keyIdentifier in keyIdentifiers)
            {
                var kvKey = await _client.GetKeyAsync(keyIdentifier.Identifier.Identifier);
                Jwk key = null;

                switch (kvKey.Key.Kty)
                {
                    case JsonWebKeyType.Octet:
                        key = new SymmetricJwk(kvKey.Key.K);
                        break;
                    case JsonWebKeyType.Rsa:
                    case JsonWebKeyType.RsaHsm:
                        key = new RsaJwk(kvKey.Key.ToRSAParameters());
                        break;
                    case JsonWebKeyType.EllipticCurve:
                    case JsonWebKeyType.EllipticCurveHsm:
                        var parameters = kvKey.Key.ToEcParameters();
                        key = ECJwk.FromParameters(ConvertToECParameters(parameters));
                        break;
                    default:
                        continue;
                }

                key.Kid = kvKey.Key.Kid;
                if (kvKey.Key.KeyOps != null)
                {
                    for (int i = 0; i < kvKey.Key.KeyOps.Count; i++)
                    {
                        key.KeyOps.Add(kvKey.Key.KeyOps[i]);
                    }
                }
            }

            return keys;
        }

        private static SscECParameters ConvertToECParameters(KVECParameters inputParameters)
        {
            ECCurve curve;
            switch (inputParameters.Curve)
            {
                case "P-256":
                    curve = ECCurve.NamedCurves.nistP256;
                    break;
                case "P-384":
                    curve = ECCurve.NamedCurves.nistP384;
                    break;
                case "P521":
                    curve = ECCurve.NamedCurves.nistP521;
                    break;
                default:
                    throw new NotSupportedException();
            }

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