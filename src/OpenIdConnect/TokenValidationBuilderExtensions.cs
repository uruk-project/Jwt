using JsonWebToken.Internal;
using System;

namespace JsonWebToken
{
    public static class TokenValidationBuilderExtensions
    {
        public static TokenValidationPolicyBuilder RequireAuthenticationContextClassReference(this TokenValidationPolicyBuilder builder, string requiredAcr)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            return builder.AddValidation(new AuthenticationContextClassReferenceValidation(requiredAcr));
        }

        public static TokenValidationPolicyBuilder RequireAuthTime(this TokenValidationPolicyBuilder builder)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            return builder.AddValidation(new RequiredClaimValidation<int>(Claims.AuthTime));
        }

        public static TokenValidationPolicyBuilder RequireNonce(this TokenValidationPolicyBuilder builder)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            return builder.AddValidation(new RequiredClaimValidation<string>(Claims.Nonce));
        }
    }
}
