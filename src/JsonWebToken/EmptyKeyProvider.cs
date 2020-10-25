// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

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

        /// <summary>
        /// Gets the list of <see cref="Jwk"/>.
        /// </summary>
        /// <param name="header"></param>
        /// <returns></returns>
        public Jwk[] GetKeys(JwtHeaderDocument2 header)
        {
            return _empty;
        }

        /// <summary>
        /// Gets the list of <see cref="Jwk"/>.
        /// </summary>
        /// <param name="header"></param>
        /// <returns></returns>
        public Jwk[] GetKeys(JwtHeaderDocument header)
        {
            return _empty;
        }
    }
}
