// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;

namespace JsonWebToken.Internal
{
    internal sealed class LifetimeValidator : IValidator
    {
        private readonly bool _requireExpirationTime;
        private readonly long _clockSkewTicks;

        public LifetimeValidator(bool requireExpirationTime, int clockSkewInSeconds)
        {
            _requireExpirationTime = requireExpirationTime;
            _clockSkewTicks = clockSkewInSeconds;
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

            var utcNow = DateTime.UtcNow.ToEpochTime();
            if (expires.HasValue && (expires.Value < utcNow - _clockSkewTicks))
            {
                return TokenValidationResult.Expired(jwt);
            }

            var notBefore = jwt.Payload.Nbf;
            if (notBefore.HasValue && (notBefore.Value > utcNow + _clockSkewTicks))
            {
                return TokenValidationResult.NotYetValid(jwt);
            }

            return TokenValidationResult.Success(jwt);
        }
    }
}
