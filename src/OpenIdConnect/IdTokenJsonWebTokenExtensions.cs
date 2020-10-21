// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    public static class IdTokenJsonWebTokenExtensions
    {
        public static IdToken AsIdToken(this JwtOld token)
        {
            return new IdToken(token);
        }
    }
}