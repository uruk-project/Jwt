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
        [Obsolete("This method is obsolete. Use TryValidate(JwtHeaderDocument header, JwtPayloadDocument payload, out TokenValidationError? error) instead.")]
        public TokenValidationResult TryValidate(Jwt jwt)
        {
            if (jwt is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.jwt);
            }

            if (jwt.Payload is null)
            {
                return TokenValidationResult.MalformedToken();
            }

            if (!jwt.Payload.TryGetClaim(Claims.ExpUtf8, out var exp) && exp.ValueKind != System.Text.Json.JsonValueKind.Number)
            {
                return TokenValidationResult.MissingClaim(jwt, Claims.ExpUtf8);
            }

            if (!_tokenReplayCache.TryAdd(jwt, EpochTime.ToDateTime(exp.GetInt64())))
            {
                return TokenValidationResult.TokenReplayed(jwt);
            }

            return TokenValidationResult.Success(jwt);
        }

        public bool TryValidate(JwtHeaderDocument header, JwtPayloadDocument payload, [NotNullWhen(false)] out TokenValidationError? error)
        {
            if (!payload.TryGetClaim(Claims.ExpUtf8, out var expires))
            {
                error = TokenValidationError.MissingClaim(Claims.ExpUtf8);
                return false;
            }

            if (!payload.TryGetClaim(Claims.JtiUtf8, out var jti))
            {
                error = TokenValidationError.MissingClaim(Claims.JtiUtf8);
                return false;
            }

            if (!_tokenReplayCache.TryAdd(jti.GetString(), expires.GetInt64()))
            {
                error = TokenValidationError.TokenReplayed();
                return false;
            }

            error = null;
            return true;
        }
    }
}
