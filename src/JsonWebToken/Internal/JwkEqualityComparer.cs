using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace JsonWebToken
{
    internal sealed class JwkEqualityComparer : IEqualityComparer<CryprographicFactoryKey>
    {
        public static JwkEqualityComparer Default { get; } = new JwkEqualityComparer();

        /// <inheritdoc />
        public bool Equals(CryprographicFactoryKey left, CryprographicFactoryKey right)
        {
            return ReferenceEquals(left.Key, right.Key) && left.Algorithm == right.Algorithm;
        }

        /// <inheritdoc />
        public int GetHashCode(CryprographicFactoryKey value)
        {
            return RuntimeHelpers.GetHashCode(value.Key) ^ value.Algorithm.GetHashCode();
        }
    }
}