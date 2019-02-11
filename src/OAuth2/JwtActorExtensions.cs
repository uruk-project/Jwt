// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using System;

namespace JsonWebToken
{
    public static class JwtActorExtensions
    {
        public static Actor GetActor(this Jwt token)
        {
            if (token == null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            var json = (string)token.Payload[OAuth2Claims.ActUtf8];
            return json == null ? null : Actor.FromJson(json);
        }
    }
}
