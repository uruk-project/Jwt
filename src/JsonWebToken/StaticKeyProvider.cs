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
        private readonly JsonWebKeySet _jwks;

        public StaticKeyProvider(JsonWebKeySet jwks)
        {
            _jwks = jwks ?? throw new ArgumentNullException(nameof(jwks));
        }

        public IReadOnlyList<JsonWebKey> GetKeys(JwtHeader header)
        {
            var kid = header.Kid;
            return _jwks.GetKeys(kid);
        }

        public static implicit operator StaticKeyProvider(JsonWebKeySet keys) => new StaticKeyProvider(keys);
        public static implicit operator StaticKeyProvider(JsonWebKey key) => new StaticKeyProvider(new JsonWebKeySet(key));
    }
}
