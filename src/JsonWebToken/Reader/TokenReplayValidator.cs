// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;

namespace JsonWebToken
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
            if (!payload.TryGetClaim(JwtClaimNames.Exp.EncodedUtf8Bytes, out var expires))
            {
                error = TokenValidationError.MissingClaim(JwtClaimNames.Exp.ToString());
                return false;
            }

            if (!payload.TryGetClaim(JwtClaimNames.Jti.EncodedUtf8Bytes, out var jti))
            {
                error = TokenValidationError.MissingClaim(JwtClaimNames.Jti.ToString());
                return false;
            }

            if (!_tokenReplayCache.TryAdd(jti.GetString(), expires.GetInt64()))
            {
                error = TokenValidationError.TokenReplayed();
                return false;
            }

#if NET5_0_OR_GREATER
            Unsafe.SkipInit(out error);
#else
            error = default;
#endif
            return true;
        }
    }
}
