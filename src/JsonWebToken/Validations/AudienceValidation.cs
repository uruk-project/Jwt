using System;
using System.Collections.Generic;

namespace JsonWebToken.Validations
{
    public class AudienceValidation : IValidation
    {
        private readonly IEnumerable<string> _audiences;

        public AudienceValidation(IEnumerable<string> audiences)
        {
            _audiences = audiences;
        }

        public TokenValidationResult TryValidate(TokenValidationContext context)
        {
            var jwt = context.Jwt;
            bool missingAudience = true;
            foreach (string audience in jwt.Audiences)
            {
                missingAudience = false;
                if (string.IsNullOrWhiteSpace(audience))
                {
                    continue;
                }

                foreach (string validAudience in _audiences)
                {
                    if (string.Equals(audience, validAudience, StringComparison.Ordinal))
                    {
                        return TokenValidationResult.Success(jwt);
                    }
                }
            }

            if (missingAudience)
            {
                return TokenValidationResult.MissingClaim(jwt, Claims.Aud);
            }

            return TokenValidationResult.InvalidClaim(jwt, Claims.Aud);
        }
    }
}
