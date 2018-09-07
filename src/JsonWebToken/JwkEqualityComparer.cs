using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace JsonWebToken
{
    internal sealed class JwkEqualityComparer : IEqualityComparer<ProviderFactoryKey>
    {
        public static JwkEqualityComparer Default { get; } = new JwkEqualityComparer();

        /// <inheritdoc />
        public bool Equals(ProviderFactoryKey left, ProviderFactoryKey right)
        {
            return ReferenceEquals(left.Key, right.Key) && left.Algorithm == right.Algorithm;
        }

        /// <inheritdoc />
        public int GetHashCode(ProviderFactoryKey value)
        {
            return RuntimeHelpers.GetHashCode(value.Key) ^ value.Algorithm.GetHashCode();
        }
    }
}