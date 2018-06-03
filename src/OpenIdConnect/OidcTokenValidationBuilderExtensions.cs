using System.Threading;

namespace JsonWebTokens
{
    public static class OidcTokenValidationBuilderExtensions
    {
        /// <summary>
        /// Add configuration from the OIDC configuration, including issuer validation and signature requirement.
        /// </summary>
        /// <param name="builder"></param>
        /// <param name="metadataAddress"></param>
        /// <returns></returns>
        public static TokenValidationBuilder AddOpenIdConfiguration(this TokenValidationBuilder builder, string metadataAddress)
        {
            var retriever = new OpenIdConnectConfigurationRetriever();
            var config = retriever.GetConfiguration(metadataAddress, new HttpDocumentRetriever(), CancellationToken.None);

            builder.RequireIssuer(config.Issuer);
            return builder.RequireSignature(config.JwksUri);
        }
    }
}
