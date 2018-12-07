﻿// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using System;

namespace JsonWebToken
{
    public static class SetJsonWebTokenExtensions
    {
        public static SecurityEventToken AsSecurityEventToken(this Jwt token)
        {
            if (!token.Payload.ContainsKey(SetClaims.Events))
            {
                throw new InvalidOperationException();
            }

            return new SecurityEventToken(token);
        }
    }
}