// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;

namespace JsonWebToken
{
    /// <summary>
    /// Represents a static provider of keys.
    /// </summary>
    public sealed class StaticKeyProvider : IKeyProvider
    {
        private readonly Jwks _jwks;

        /// <summary>
        /// Initializes a new instance of <see cref="StaticKeyProvider"/>.
        /// </summary>
        /// <param name="jwks"></param>
        public StaticKeyProvider(Jwks jwks)
        {
            if (jwks == null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.jwks);
            }

            _jwks = jwks;
        }

        /// <summary>
        /// Gets the list of <see cref="Jwk"/>.
        /// </summary>
        /// <param name="header"></param>
        /// <returns></returns>
        public Jwk[] GetKeys(JwtHeader header)
        {
            var kid = header.Kid;
            return _jwks.GetKeys(kid);
        }

        /// <summary>
        /// Converts a <see cref="Jwks"/> to <see cref="StaticKeyProvider"/>.
        /// </summary>
        /// <param name="keys"></param>
        public static implicit operator StaticKeyProvider(Jwks keys) => new StaticKeyProvider(keys);

        /// <summary>
        /// Converts a <see cref="Jwk"/> to <see cref="StaticKeyProvider"/>.
        /// </summary>
        /// <param name="key"></param>
        public static implicit operator StaticKeyProvider(Jwk key) => new StaticKeyProvider(new Jwks(key));
    }
}
