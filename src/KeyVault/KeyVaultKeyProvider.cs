// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text.Json;
using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;

namespace JsonWebToken.KeyVault
{
    public sealed class KeyVaultKeyProvider : CachedKeyProvider
    {
        private readonly KeyClient _client;

        public override string Issuer => _client.VaultUri.ToString();

        /// <summary>Initializes a new instance of the <see cref="KeyVaultKeyProvider"/> class.</summary>
        public KeyVaultKeyProvider(KeyClient client, long minimumRefreshInterval = DefaultMinimumRefreshInterval, long automaticRefreshInterval = DefaultAutomaticRefreshInterval)
            : base(minimumRefreshInterval, automaticRefreshInterval)
        {
            _client = client ?? throw new ArgumentNullException(nameof(client));
        }

        /// <summary>Initializes a new instance of the <see cref="KeyVaultKeyProvider"/> class with default credentials. See <see cref="DefaultAzureCredential"/>.</summary>
        public KeyVaultKeyProvider(string vaultUri, long minimumRefreshInterval = DefaultMinimumRefreshInterval, long automaticRefreshInterval = DefaultAutomaticRefreshInterval)
            : base(minimumRefreshInterval, automaticRefreshInterval)
        {
            if (vaultUri is null)
            {
                throw new ArgumentNullException(nameof(vaultUri));
            }

            _client = new KeyClient(new Uri(vaultUri), new DefaultAzureCredential());
        }

        /// <summary>Initializes a new instance of the <see cref="KeyVaultKeyProvider"/> class.</summary>
        public KeyVaultKeyProvider(string vaultUri, TokenCredential credential, long minimumRefreshInterval = DefaultMinimumRefreshInterval, long automaticRefreshInterval = DefaultAutomaticRefreshInterval)
            : base(minimumRefreshInterval, automaticRefreshInterval)
        {
            if (vaultUri is null)
            {
                throw new ArgumentNullException(nameof(vaultUri));
            }

            if (credential is null)
            {
                throw new ArgumentNullException(nameof(credential));
            }

            _client = new KeyClient(new Uri(vaultUri), credential);
        }

        protected override Jwks GetKeysFromSource()
        {
            var keys = new List<Jwk>();

            foreach (var keyProperties in _client.GetPropertiesOfKeys())
            {
                var kvKey = _client.GetKey(keyProperties.Name);
                Jwk? key = null;
                if (kvKey.Value.KeyType == KeyType.Oct)
                {
                    key = SymmetricJwk.FromByteArray(kvKey.Value.Key.K, false);
                }
                else if (kvKey.Value.KeyType == KeyType.Rsa || kvKey.Value.KeyType == KeyType.RsaHsm)
                {
                    key = RsaJwk.FromParameters(kvKey.Value.Key.ToRSA(true).ExportParameters(true), false);
                }
#if !NETFRAMEWORK
                else if (kvKey.Value.KeyType == KeyType.Ec || kvKey.Value.KeyType == KeyType.EcHsm)
                {
                    ECJwk.FromParameters(ConvertToECParameters(kvKey.Value), computeThumbprint: false);
                }
#endif

                if (key is not null)
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

            return new Jwks(_client.VaultUri.ToString(), keys);
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