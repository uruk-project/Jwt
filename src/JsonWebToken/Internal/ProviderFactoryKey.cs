using System;

namespace JsonWebToken
{
    internal readonly struct ProviderFactoryKey
    {
        public readonly JsonWebKey Key;

        public readonly int Algorithm;

        public ProviderFactoryKey(JsonWebKey key, int algorithm)
        {
            Key = key ?? throw new ArgumentNullException(nameof(key));
            Algorithm = algorithm;
        }
    }
}