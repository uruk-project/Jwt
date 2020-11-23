using System;
using System.Buffers;
using System.Runtime.CompilerServices;

namespace JsonWebToken.Performance
{
    internal class FixedSizedBufferWriter : IBufferWriter<byte>
    {
        private readonly byte[] _buffer;
        private int _count;

        public FixedSizedBufferWriter(int capacity)
        {
            _buffer = new byte[capacity];
        }

        public void Clear()
        {
            _count = 0;
        }

        public byte[] Buffer => _buffer;

        public Memory<byte> GetMemory(int minimumLength = 0) => _buffer.AsMemory(_count);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public Span<byte> GetSpan(int minimumLength = 0) => _buffer.AsSpan(_count);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Advance(int bytes)
        {
            _count += bytes;
        }
    }
}
