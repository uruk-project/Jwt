// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    public static class OidcTokenValidationBuilderExtensions
    {
        /// <summary>Add configuration from the OIDC configuration, including issuer validation and signature requirement.</summary>
        public static TokenValidationPolicyBuilder AddOpenIdConfiguration(this TokenValidationPolicyBuilder builder, string metadataAddress, SignatureAlgorithm algorithm)
        {
            return builder.RequireMetadataConfiguration(metadataAddress, algorithm);
        }
    }
}
