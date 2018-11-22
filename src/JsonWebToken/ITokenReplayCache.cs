// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;

namespace JsonWebToken
{
    /// <summary>
    /// Interface that defines a simple cache for tacking replaying of tokens.
    /// </summary>
    public interface ITokenReplayCache
    {
        /// <summary>
        /// Try to add a token.
        /// </summary>
        /// <param name="jwtToken">the token to add.</param>
        /// <param name="expiresOn">the time when token expires.</param>
        /// <returns>true if the token was successfully added.</returns>
        bool TryAdd(Jwt jwtToken, DateTime expiresOn);
    }
}
