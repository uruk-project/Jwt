using System;

namespace JsonWebToken
{
    public class StaticKeyProvider : IKeyProvider
    {
        private readonly JsonWebKeySet _jwks;

        public StaticKeyProvider(JsonWebKeySet jwks)
        {
            _jwks = jwks ?? throw new ArgumentNullException(nameof(jwks));
        }

        public JsonWebKeySet GetKeys(JsonWebToken jwtToken)
        {
            return _jwks;
        }
    }
}
