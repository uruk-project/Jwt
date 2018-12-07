// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using Newtonsoft.Json.Linq;
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

            var json = token.Payload[OAuth2Claims.Act]?.Value<string>();
            return json == null ? null : Actor.FromJson(json);
        }
    }
}
