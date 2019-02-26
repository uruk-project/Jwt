// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;

namespace JsonWebToken
{
    /// <summary>
    /// Represents the context for validating a token.
    /// </summary>
    public readonly ref struct TokenValidationContext
    {
        /// <summary>
        /// Initializes a new instance of <see cref="TokenValidationContext"/>.
        /// </summary>
        /// <param name="jwt"></param>
        public TokenValidationContext(Jwt jwt)
        {
            Jwt = jwt;
        }

        /// <summary>
        /// The decoded JWT.
        /// </summary>
        public readonly Jwt Jwt;
    }
}
