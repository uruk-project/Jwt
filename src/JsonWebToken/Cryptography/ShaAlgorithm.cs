using System;
#if NETCOREAPP3_0
#endif

namespace JsonWebToken
{
    public abstract class ShaAlgorithm
    {
        public abstract void ComputeHash(ReadOnlySpan<byte> src, Span<byte> destination, ReadOnlySpan<byte> prepend = default);

        public abstract int HashSize { get; }
    }
}
