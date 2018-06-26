using System;

namespace JsonWebToken.Validations
{
    public class LifetimeValidation : IValidation
    {
        private readonly bool _requireExpirationTime;
        private readonly TimeSpan _clockSkew;
        private readonly TimeSpan _negativeClockSkew;

        public LifetimeValidation(bool requireExpirationTime, int clockSkew)
        {
            _requireExpirationTime = requireExpirationTime;
            _clockSkew = TimeSpan.FromSeconds(clockSkew);
            _negativeClockSkew = TimeSpan.FromSeconds(-clockSkew);
        }

        public TokenValidationResult TryValidate(TokenValidationContext context)
        {
            var jwt = context.Jwt;
            var expires = jwt.Payload.Exp;
            if (!expires.HasValue && _requireExpirationTime)
            {
                return TokenValidationResult.MissingClaim(jwt, Claims.Exp);
            }

            var utcNow = DateTime.UtcNow;
            if (expires.HasValue && (expires.Value < DateTimeUtil.Add(utcNow, _negativeClockSkew)))
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
