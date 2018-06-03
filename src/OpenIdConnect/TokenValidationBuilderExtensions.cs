using JsonWebTokens;
using JsonWebTokens.Validations;
using System;

namespace JsonWebTokens
{
    public static class TokenValidationBuilderExtensions
    {
        public static TokenValidationBuilder RequireAuthenticationContextClassReference(this TokenValidationBuilder builder, string requiredAcr)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            return builder.AddValidation(new AuthenticationContextClassReferenceValidation(requiredAcr));
        }

        public static TokenValidationBuilder RequireAuthTime(this TokenValidationBuilder builder)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            return builder.AddValidation(new RequiredClaimValidation<int>(ClaimNames.AuthTime));
        }

        public static TokenValidationBuilder RequireNonce(this TokenValidationBuilder builder)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            return builder.AddValidation(new RequiredClaimValidation<string>(ClaimNames.Nonce));
        }
    }
}
