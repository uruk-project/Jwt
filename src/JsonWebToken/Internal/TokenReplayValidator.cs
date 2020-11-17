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

        public bool TryValidate(JwtHeaderDocument header, JwtPayloadDocument payload, [NotNullWhen(false)] out TokenValidationError? error)
        {
            if (!payload.TryGetClaim(Claims.Exp.EncodedUtf8Bytes, out var expires))
            {
                error = TokenValidationError.MissingClaim(Claims.Exp.ToString());
                return false;
            }

            if (!payload.TryGetClaim(Claims.Jti.EncodedUtf8Bytes, out var jti))
            {
                error = TokenValidationError.MissingClaim(Claims.Jti.ToString());
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
