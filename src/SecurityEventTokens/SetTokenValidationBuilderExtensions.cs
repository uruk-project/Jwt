namespace JsonWebTokens
{
    public static class SetTokenValidationBuilderExtensions
    {
        public static TokenValidationBuilder RequireSecurityEventToken(this TokenValidationBuilder builder)
        {
            if (builder == null)
            {
                throw new System.ArgumentNullException(nameof(builder));
            }

            builder.RequireClaim(ClaimNames.Events);

            return builder;
        }
    }
}