using System;

namespace JsonWebToken.Internal
{
    internal readonly struct CryptographicFactoryKey
    {
        public readonly JsonWebKey Key;

        public readonly int Algorithm;

        public CryptographicFactoryKey(JsonWebKey key, int algorithm)
        {
            Key = key ?? throw new ArgumentNullException(nameof(key));
            Algorithm = algorithm;
        }
    }
}