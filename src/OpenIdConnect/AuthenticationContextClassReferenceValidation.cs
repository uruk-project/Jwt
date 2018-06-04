using JsonWebToken;
using Newtonsoft.Json.Linq;
using System;

namespace JsonWebToken
{
    public class AuthenticationContextClassReferenceValidation : IValidation
    {
        private readonly string _requiredAcr;

        public AuthenticationContextClassReferenceValidation(string requiredAcr)
        {
            _requiredAcr = requiredAcr;
        }

        public TokenValidationResult TryValidate(TokenValidationContext context)
        {
            var jwt = context.Jwt;
            var act = jwt.Payload[ClaimNames.Acr];
            if (act == null || act.Type == JTokenType.Null)
            {
                return TokenValidationResult.MissingClaim(jwt, ClaimNames.Acr);
            }

            if (string.Equals(_requiredAcr, act.Value<string>(), StringComparison.Ordinal))
            {
                return TokenValidationResult.InvalidClaim(jwt, ClaimNames.Acr);
            }

            return TokenValidationResult.Success(jwt);
        }
    }
}
