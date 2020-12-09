// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    /// <summary>Represents the claims contained in the JWT.</summary>
    public sealed class JwtPayload : JsonObject
    {
        /// <summary>Initializes a new instance of the <see cref="JwtPayload"/> class.</summary>
        public JwtPayload()
            : base(MemberStore.CreateFastGrowingStore())
        {
        }
    }
}