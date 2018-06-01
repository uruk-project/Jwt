using JsonWebToken;
using System;

namespace JsonWebToken
{
    public static class TokenValidationBuilderExtensions
    {
        public static TokenValidationBuilder RequireEvents(this TokenValidationBuilder builder)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            return builder.AddValidation(new AuthenticationContextClassReferenceValidation(""));
        }
    }
}
