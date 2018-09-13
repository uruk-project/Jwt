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
    }
}
