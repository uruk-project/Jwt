using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;

namespace JsonWebToken.Internal
{
    public class RequiredClaimListValidation<TClaim> : IValidation
    {
        private readonly string _claim;
        private readonly IList<TClaim> _values;

        public RequiredClaimListValidation(string claim, IList<TClaim> values)
        {
            _claim = claim ?? throw new ArgumentNullException(nameof(claim));
            _values = values ?? throw new ArgumentNullException(nameof(values));
        }

        public TokenValidationResult TryValidate(in TokenValidationContext context)
        {
            var jwt = context.Jwt;
            var claim = jwt.Payload[_claim];
            if (claim == null || claim.Type == JTokenType.Null)
            {
                return TokenValidationResult.MissingClaim(jwt, _claim);
            }

            for (int i = 0; i < _values.Count; i++)
            {                
                if (_values[i].Equals(claim.Value<TClaim>()))
                {
                    return TokenValidationResult.Success(jwt);
                }
            }

            return TokenValidationResult.InvalidClaim(jwt, _claim);
        }
    }
}
