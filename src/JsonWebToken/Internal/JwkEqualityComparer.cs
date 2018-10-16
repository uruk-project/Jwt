using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace JsonWebToken.Internal
{
    internal sealed class JwkEqualityComparer : IEqualityComparer<CryptographicFactoryKey>
    {
        public static JwkEqualityComparer Default { get; } = new JwkEqualityComparer();

        public bool Equals(CryptographicFactoryKey left, CryptographicFactoryKey right)
        {
            return ReferenceEquals(left.Key, right.Key) && left.Algorithm == right.Algorithm;
        }

        public int GetHashCode(CryptographicFactoryKey value)
        {
            return RuntimeHelpers.GetHashCode(value.Key) ^ value.Algorithm.GetHashCode();
        }
    }
}