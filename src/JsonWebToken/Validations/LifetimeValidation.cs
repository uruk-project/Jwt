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

        public TokenValidationResult TryValidate(JsonWebToken jwt)
        {
            var expires = jwt.Payload.Exp;

            if (!expires.HasValue && _requireExpirationTime)
            {
                return TokenValidationResult.NoExpiration(jwt);
            }

            var notBefore = jwt.Payload.Nbf;
            if (notBefore.HasValue && expires.HasValue && (notBefore.Value > expires.Value))
            {
                return TokenValidationResult.InvalidLifetime(jwt);
            }

            var utcNow = EpochTime.GetIntDate(DateTime.UtcNow);
            if (notBefore.HasValue && (notBefore.Value > DateTimeUtil.Add(utcNow, _clockSkew)))
            {
                return TokenValidationResult.NotYetValid(jwt);
            }

            if (expires.HasValue && (expires.Value < DateTimeUtil.Add(utcNow, -_clockSkew)))
            {
                return TokenValidationResult.Expired(jwt);
            }

            return TokenValidationResult.Success(jwt);
        }
    }
}
