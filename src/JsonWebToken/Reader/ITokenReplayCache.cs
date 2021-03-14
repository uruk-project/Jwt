// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;

namespace JsonWebToken
{
    /// <summary>Interface that defines a simple cache for tacking replaying of tokens.</summary>
    public interface ITokenReplayCache
    {
        /// <summary>Try to add a token.</summary>
        /// <param name="jwtToken">The token to add.</param>
        /// <param name="expiresOn">The time when token expires.</param>
        /// <returns>true if the token was successfully added.</returns>
        bool TryAdd(Jwt jwtToken, DateTime expiresOn);

        /// <summary>Try to add a token.</summary>
        /// <param name="jwtId">The token to add.</param>
        /// <param name="expiresOn">The time when token expires.</param>
        /// <returns>true if the token was successfully added.</returns>
        bool TryAdd(string? jwtId, long? expiresOn);
    }
}
