using System;

namespace JsonWebToken.Validations
{
    public class LifetimeValidation : IValidation
    {
        private readonly bool _requireExpirationTime;
        private readonly int _clockSkew;

        public LifetimeValidation(bool requireExpirationTime, int clockSkew)
        {
            _requireExpirationTime = requireExpirationTime;
            _clockSkew = clockSkew;
        }

        public TokenValidationResult TryValidate(TokenValidationContext context)
        {
            var jwt = context.Jwt;
            var expires = jwt.Payload.Exp;
            if (!expires.HasValue && _requireExpirationTime)
            {
                return TokenValidationResult.MissingClaim(jwt, ClaimNames.Exp);
            }

            var utcNow = EpochTime.GetIntDate(DateTime.UtcNow);
            if (expires.HasValue && (expires.Value < DateTimeUtil.Add(utcNow, -_clockSkew)))
            {
                return TokenValidationResult.Expired(jwt);
            }

            var notBefore = jwt.Payload.Nbf;
            if (notBefore.HasValue && (notBefore.Value > DateTimeUtil.Add(utcNow, _clockSkew)))
            {
                return TokenValidationResult.NotYetValid(jwt);
            }


            return TokenValidationResult.Success(jwt);
        }
    }
}
