// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;

namespace JsonWebToken
{
    public static class SetJsonWebTokenExtensions
    {
        public static SecurityEventToken AsSecurityEventToken(this Jwt token)
        {
            if (token is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.jwt);
            }

            if (token.Payload is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.payload);
            }

            if (!token.Payload.ContainsKey(SetClaims.EventsUtf8))
            {
                throw new InvalidOperationException();
            }

            return new SecurityEventToken(token);
        }
    }
}