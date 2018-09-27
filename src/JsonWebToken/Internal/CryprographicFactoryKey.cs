using System;

namespace JsonWebToken
{
    internal readonly struct CryprographicFactoryKey
    {
        public readonly JsonWebKey Key;

        public readonly int Algorithm;

        public CryprographicFactoryKey(JsonWebKey key, int algorithm)
        {
            Key = key ?? throw new ArgumentNullException(nameof(key));
            Algorithm = algorithm;
        }
    }
}