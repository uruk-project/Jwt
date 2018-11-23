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

        public StaticKeyProvider(Jwks jwks)
        {
            _jwks = jwks ?? throw new ArgumentNullException(nameof(jwks));
        }

        public IReadOnlyList<Jwk> GetKeys(JwtHeader header)
        {
            var kid = header.Kid;
            return _jwks.GetKeys(kid);
        }

        public static implicit operator StaticKeyProvider(Jwks keys) => new StaticKeyProvider(keys);
        public static implicit operator StaticKeyProvider(Jwk key) => new StaticKeyProvider(new Jwks(key));
    }
}
