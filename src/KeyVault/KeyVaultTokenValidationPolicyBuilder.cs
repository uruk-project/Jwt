// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using Azure.Core;
using Azure.Security.KeyVault.Keys;
using JsonWebToken.KeyVault;

namespace JsonWebToken
{
    public static class KeyVaultTokenValidationPolicyBuilder
    {
        /// <summary>Configure the signature behavior with Key Vault for a specific <paramref name="vaultUri"/>.</summary>
        public static TokenValidationPolicyBuilder RequireSignatureWithKeyVault(this TokenValidationPolicyBuilder builder, string vaultUri, TokenCredential credentials, SignatureAlgorithm algorithm, long minimumRefreshInterval = CachedKeyProvider.DefaultMinimumRefreshInterval, long automaticRefreshInterval = CachedKeyProvider.DefaultAutomaticRefreshInterval)
            => builder.RequireSignature(vaultUri, new KeyVaultKeyProvider(vaultUri, credentials, minimumRefreshInterval, automaticRefreshInterval), algorithm);

        /// <summary>Configure the signature behavior with Key Vault for a specific <paramref name="vaultUri"/>.</summary>
        public static TokenValidationPolicyBuilder RequireSignatureWithKeyVault(this TokenValidationPolicyBuilder builder, string vaultUri, SignatureAlgorithm algorithm, long minimumRefreshInterval = CachedKeyProvider.DefaultMinimumRefreshInterval, long automaticRefreshInterval = CachedKeyProvider.DefaultAutomaticRefreshInterval)
            => builder.RequireSignature(vaultUri, new KeyVaultKeyProvider(vaultUri, minimumRefreshInterval, automaticRefreshInterval), algorithm);

        /// <summary>Configure the signature behavior with Key Vault for a specific <paramref name="client"/>.</summary>
        public static TokenValidationPolicyBuilder RequireSignatureWithKeyVault(this TokenValidationPolicyBuilder builder, KeyClient client, SignatureAlgorithm algorithm, long minimumRefreshInterval = CachedKeyProvider.DefaultMinimumRefreshInterval, long automaticRefreshInterval = CachedKeyProvider.DefaultAutomaticRefreshInterval)
            => builder.RequireSignature(client.VaultUri.ToString(), new KeyVaultKeyProvider(client, minimumRefreshInterval, automaticRefreshInterval), algorithm);
    }
}