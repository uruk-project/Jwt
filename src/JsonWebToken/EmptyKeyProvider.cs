// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;

namespace JsonWebToken
{
    /// <summary>
    /// Represents a static provider of keys.
    /// </summary>
    public sealed class EmptyKeyProvider : IKeyProvider
    {
        private static readonly Jwk[] _empty = Array.Empty<Jwk>();

        /// <summary>
        /// Gets the list of <see cref="Jwk"/>.
        /// </summary>
        /// <param name="header"></param>
        /// <returns></returns>
        public Jwk[] GetKeys(JwtHeader header)
        {            
            return _empty;
        }
    }
}
