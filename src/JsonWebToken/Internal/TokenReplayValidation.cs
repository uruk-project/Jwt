﻿// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;

namespace JsonWebToken.Internal
{
    public class TokenReplayValidation : IValidation
    {
        private readonly ITokenReplayCache _tokenReplayCache;

        public TokenReplayValidation(ITokenReplayCache tokenReplayCache)
        {
            _tokenReplayCache = tokenReplayCache ?? throw new ArgumentNullException(nameof(tokenReplayCache));
        }

        public string Name => nameof(TokenReplayValidation);

        public TokenValidationResult TryValidate(in TokenValidationContext context)
        {
            var jwt = context.Jwt;

            var expires = jwt.ExpirationTime;
            if (!expires.HasValue)
            {
                return TokenValidationResult.MissingClaim(jwt, Claims.Exp);
            }

            if (!_tokenReplayCache.TryAdd(jwt, expires.Value))
            {
                return TokenValidationResult.TokenReplayed(jwt);
            }

            return TokenValidationResult.Success(jwt);
        }
    }
}
