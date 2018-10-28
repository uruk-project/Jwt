// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;

namespace JsonWebToken.Internal
{
    public class LifetimeValidator : IValidator
    {
        private readonly bool _requireExpirationTime;
        private readonly long _clockSkewTicks;
        private readonly long _negativeClockSkewTicks;

        public LifetimeValidator(bool requireExpirationTime, int clockSkewInSeconds)
        {
            _requireExpirationTime = requireExpirationTime;
            _clockSkewTicks = clockSkewInSeconds * TimeSpan.TicksPerSecond;
            _negativeClockSkewTicks = -_clockSkewTicks;
        }

        /// <inheritdoc />
        public TokenValidationResult TryValidate(in TokenValidationContext context)
        {
            var jwt = context.Jwt;
            var expires = jwt.Payload.Exp;
            if (!expires.HasValue && _requireExpirationTime)
            {
                return TokenValidationResult.MissingClaim(jwt, Claims.Exp);
            }

            var utcNow = DateTime.UtcNow;
            if (expires.HasValue && (expires.Value < utcNow.AddSafe(_negativeClockSkewTicks)))
            {
                return TokenValidationResult.Expired(jwt);
            }

            var notBefore = jwt.Payload.Nbf;
            if (notBefore.HasValue && (notBefore.Value > utcNow.AddSafe(_clockSkewTicks)))
            {
                return TokenValidationResult.NotYetValid(jwt);
            }
            
            return TokenValidationResult.Success(jwt);
        }
    }
}
