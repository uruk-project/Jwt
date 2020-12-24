// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;
using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;

namespace JsonWebToken.KeyVault
{
    public sealed class KeyVaultKeyProvider : IKeyProvider
    {
        private readonly string _issuer;
        private readonly KeyClient _client;

        public int MaxResults { get; set; } = 10;

        public string Issuer => _issuer;

        /// <summary>Initializes a new instance of the <see cref="KeyVaultKeyProvider"/> class.</summary>
        public KeyVaultKeyProvider(string issuer, KeyClient client)
        {
            _issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
            _client = client ?? throw new ArgumentNullException(nameof(client));
        }

        /// <summary>Initializes a new instance of the <see cref="KeyVaultKeyProvider"/> class with default credentials. See <see cref="DefaultAzureCredential"/>.</summary>
        public KeyVaultKeyProvider(string issuer, string vaultUri)
        {
            if (vaultUri is null)
            {
                throw new ArgumentNullException(nameof(vaultUri));
            }

            _issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
            _client = new KeyClient(new Uri(vaultUri), new DefaultAzureCredential());
        }

        /// <summary>Initializes a new instance of the <see cref="KeyVaultKeyProvider"/> class.</summary>
        public KeyVaultKeyProvider(string issuer, string vaultUri, TokenCredential credential)
        {
            if (vaultUri is null)
            {
                throw new ArgumentNullException(nameof(vaultUri));
            }

            if (credential is null)
            {
                throw new ArgumentNullException(nameof(credential));
            }

            _issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
            _client = new KeyClient(new Uri(vaultUri), credential);
        }

        public Jwk[] GetKeys(JwtHeaderDocument header)
        {
            return GetKeysAsync().GetAwaiter().GetResult();
        }

        private async Task<Jwk[]> GetKeysAsync()
        {
            var keys = new List<Jwk>();
            
            await foreach (var keyProperties in _client.GetPropertiesOfKeysAsync())
            {
                var kvKey = await _client.GetKeyAsync(keyProperties.Name);
                Jwk? key = null;
                if (kvKey.Value.KeyType == KeyType.Oct)
                {
                    key = SymmetricJwk.FromByteArray(kvKey.Value.Key.K, false);
                }
                else if(kvKey.Value.KeyType == KeyType.Rsa || kvKey.Value.KeyType == KeyType.RsaHsm)
                {
                    key = RsaJwk.FromParameters(kvKey.Value.Key.ToRSA(true).ExportParameters(true), false);
                }
#if !NETFRAMEWORK
                else if (kvKey.Value.KeyType == KeyType.Ec || kvKey.Value.KeyType == KeyType.EcHsm)
                {
                    ECJwk.FromParameters(ConvertToECParameters(kvKey.Value), computeThumbprint: false);
                }
#endif

                if (!(key is null))
                {

                    key.Kid = JsonEncodedText.Encode(kvKey.Value.Key.Id);
                    if (kvKey.Value.Key.KeyOps != null)
                    {
                        foreach (var operation in kvKey.Value.Key.KeyOps)
                        {
                            key.KeyOps.Add(JsonEncodedText.Encode(operation.ToString()));
                        }
                    }

                    keys.Add(key);
                }
            }

            return keys.ToArray();
        }

#if !NETFRAMEWORK
        private static ECParameters ConvertToECParameters(KeyVaultKey key)
        {
            ECCurve curve;
            if (key.Key.CurveName == KeyCurveName.P256)
            {
                curve = ECCurve.NamedCurves.nistP256;
            } 
            else if (key.Key.CurveName == KeyCurveName.P384)
            {
                curve = ECCurve.NamedCurves.nistP384;
            }
            else if (key.Key.CurveName == KeyCurveName.P521)
            {
                curve = ECCurve.NamedCurves.nistP521;
            }
            else if (key.Key.CurveName == KeyCurveName.P256K)
            {
                curve = ECCurve.CreateFromValue("1.3.132.0.10");
            }
            else
            {
                throw new NotSupportedException();
            }

            return new ECParameters
            {
                Curve = curve,
                D = key.Key.D,
                Q = new ECPoint
                {
                    X = key.Key.X,
                    Y = key.Key.Y
                }
            };
        }
#endif
    }
}