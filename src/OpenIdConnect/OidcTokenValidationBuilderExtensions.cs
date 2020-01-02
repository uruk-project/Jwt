// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Threading;

namespace JsonWebToken
{
    public static class OidcTokenValidationBuilderExtensions
    {
        /// <summary>
        /// Add configuration from the OIDC configuration, including issuer validation and signature requirement.
        /// </summary>
        /// <param name="builder"></param>
        /// <param name="metadataAddress"></param>
        /// <returns></returns>
        public static TokenValidationPolicyBuilder AddOpenIdConfiguration(this TokenValidationPolicyBuilder builder, string metadataAddress)
        {
            var retriever = new OpenIdConnectConfigurationRetriever();
            var config = retriever.GetConfiguration(metadataAddress, new HttpDocumentRetriever(), CancellationToken.None);

            builder.RequireIssuer(config.Issuer);
            return builder.RequireSignature(config.JwksUri);
        }
    }
}
