using JsonWebToken.Internal;

namespace JsonWebToken
{
    public static class SetTokenValidationBuilderExtensions
    {
        public static TokenValidationPolicyBuilder RequireSecurityEventToken(this TokenValidationPolicyBuilder builder)
        {
            if (builder == null)
            {
                throw new System.ArgumentNullException(nameof(builder));
            }

            builder.RequireClaim(Claims.Events);

            return builder;
        }
    }
}