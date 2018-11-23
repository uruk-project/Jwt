// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

namespace JsonWebToken
{
    public static class IdTokenJsonWebTokenExtensions
    {
        public static IdToken AsIdToken(this Jwt token)
        {
            return new IdToken(token);
        }
    }
}