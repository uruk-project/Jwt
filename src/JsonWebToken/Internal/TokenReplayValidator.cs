// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Diagnostics.CodeAnalysis;

namespace JsonWebToken.Internal
{
    internal sealed class TokenReplayValidator : IValidator
    {
        private readonly ITokenReplayCache _tokenReplayCache;

        public TokenReplayValidator(ITokenReplayCache tokenReplayCache)
        {
            _tokenReplayCache = tokenReplayCache ?? throw new ArgumentNullException(nameof(tokenReplayCache));
        }

        /// <inheritdoc />
        public TokenValidationResult TryValidate(Jwt jwt)
        {
            var expires = jwt.ExpirationTime;
            if (!expires.HasValue)
            {
                return TokenValidationResult.MissingClaim(jwt, Claims.ExpUtf8);
            }

            if (!_tokenReplayCache.TryAdd(jwt, expires.Value))
            {
                return TokenValidationResult.TokenReplayed(jwt);
            }

            return TokenValidationResult.Success(jwt);
        }

        public bool TryValidate(JwtHeader header, JwtPayload payload, [NotNullWhen(false)] out TokenValidationError? error)
        {
            var expires = payload.Exp;
            if (!expires.HasValue)
            {
                error = TokenValidationError.MissingClaim(Claims.ExpUtf8);
                return false;
            }

            if (!_tokenReplayCache.TryAdd(payload.Jti, expires.Value))
            {
                error = TokenValidationError.TokenReplayed();
                return false;
            }

            error = null;
            return true;
        }

        public bool TryValidate(JwtHeader header, JwtPayloadDocument payload, [NotNullWhen(false)] out TokenValidationError? error)
        {
            var expires = payload.Exp;
            if (!expires.HasValue)
            {
                error = TokenValidationError.MissingClaim(Claims.ExpUtf8);
                return false;
            }

            if (!_tokenReplayCache.TryAdd(payload.Jti, expires.Value))
            {
                error = TokenValidationError.TokenReplayed();
                return false;
            }

            error = null;
            return true;
        }
    }
}
