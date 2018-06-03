using Newtonsoft.Json.Linq;
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

        public JsonWebKeySet GetKeys(JObject header)
        {
            return _jwks;
        }
    }
}
