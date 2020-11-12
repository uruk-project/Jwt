// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    /// <summary>Represents a provider of <see cref="Jwk"/>.</summary>
    public interface IKeyProvider
    {
        /// <summary>Gets a list of <see cref="Jwk"/>.</summary>
        Jwk[] GetKeys(JwtHeaderDocument header);
    }
}
