using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;

namespace JsonWebToken.Validations
{
    public class RequiredClaimValidation<TClaim> : IValidation
    {
        private readonly string _claim;
        private readonly TClaim _value;

        public RequiredClaimValidation(string claim, TClaim value = default)
        {
            _claim = claim ?? throw new ArgumentNullException(nameof(claim));
            _value = value;
        }

        public TokenValidationResult TryValidate(in TokenValidationContext context)
        {
            var jwt = context.Jwt;
            var claim = jwt.Payload[_claim];
            if (claim == null || claim.Type == JTokenType.Null)
            {
                return TokenValidationResult.MissingClaim(jwt, _claim);
            }

            if (_value != null && !_value.Equals(claim.Value<TClaim>()))
            {
                return TokenValidationResult.InvalidClaim(jwt, _claim);
            }

            return TokenValidationResult.Success(jwt);
        }
    }
}
