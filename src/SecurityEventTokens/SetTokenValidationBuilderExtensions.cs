namespace JsonWebToken
{
    public static class SetTokenValidationBuilderExtensions
    {
        public static TokenValidationBuilder RequireSecurityEventToken(this TokenValidationBuilder builder)
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