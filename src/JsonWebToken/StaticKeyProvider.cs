using System;
using System.Collections.Generic;

namespace JsonWebToken
{
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
