// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace JsonWebToken
{
#nullable disable
    internal sealed class PooledByteBufferWriter : IBufferWriter<byte>, IDisposable
    {
        private byte[] _rentedBuffer;
        private int _index;

        private const int MinimumBufferSize = 256;

        public PooledByteBufferWriter(int initialCapacity = MinimumBufferSize)
        {
            Debug.Assert(initialCapacity > 0);

            _rentedBuffer = ArrayPool<byte>.Shared.Rent(initialCapacity);
            _index = 0;
        }

        public byte[] Buffer
        {
            get
            {
                return _rentedBuffer;
            }
        }

        public ReadOnlyMemory<byte> WrittenMemory
        {
            get
            {
                Debug.Assert(_rentedBuffer != null);
                Debug.Assert(_index <= _rentedBuffer.Length);
                return new ReadOnlyMemory<byte>(_rentedBuffer, 0, _index);
            }
        }

        public ReadOnlySpan<byte> WrittenSpan
        {
            get
            {
                Debug.Assert(_rentedBuffer != null);
                Debug.Assert(_index <= _rentedBuffer.Length);
                return new ReadOnlySpan<byte>(_rentedBuffer, 0, _index);
            }
        }

        public int WrittenCount
        {
            get
            {
                Debug.Assert(_rentedBuffer != null);
                return _index;
            }
        }

        public int Capacity
        {
            get
            {
                Debug.Assert(_rentedBuffer != null);
                return _rentedBuffer.Length;
            }
        }

        public void Clear()
        {
            ClearHelper();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ClearHelper()
        {
            Debug.Assert(_rentedBuffer != null);
            Debug.Assert(_index <= _rentedBuffer.Length);
            new Span<byte>(_rentedBuffer, 0, _index).Clear();
            _index = 0;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Advance(int count)
        {
            Debug.Assert(_rentedBuffer != null);
            Debug.Assert(count >= 0);
            Debug.Assert(_index <= _rentedBuffer.Length - count);
            _index += count;
        }

        public void Dispose()
        {
            ClearHelper();
            ArrayPool<byte>.Shared.Return(_rentedBuffer);
        }

        public Span<byte> GetSpan(int sizeHint = 0)
        {
            CheckAndResizeBuffer(sizeHint);
            return _rentedBuffer.AsSpan(_index);
        }

        public Memory<byte> GetMemory(int sizeHint = 0)
        {
            CheckAndResizeBuffer(sizeHint);
            return _rentedBuffer.AsMemory(_index);
        }

        private void CheckAndResizeBuffer(int sizeHint)
        {
            Debug.Assert(_rentedBuffer != null);
            Debug.Assert(sizeHint >= 0);

            if (sizeHint == 0)
            {
                sizeHint = MinimumBufferSize;
            }

            int currentLength = _rentedBuffer.Length;
            int availableSpace = currentLength - _index;
            if (sizeHint > availableSpace)
            {
                int growBy = Math.Max(sizeHint, currentLength);
                int newSize = currentLength + growBy;

                byte[] oldBuffer = _rentedBuffer;

                _rentedBuffer = ArrayPool<byte>.Shared.Rent(newSize);

                Debug.Assert(oldBuffer.Length >= _index);
                Debug.Assert(_rentedBuffer.Length >= _index);

                Span<byte> previousBuffer = new Span<byte>(oldBuffer, 0, _index);
                previousBuffer.CopyTo(_rentedBuffer);
                previousBuffer.Clear();
                ArrayPool<byte>.Shared.Return(oldBuffer);
            }

            Debug.Assert(_rentedBuffer.Length - _index > 0);
            Debug.Assert(_rentedBuffer.Length - _index >= sizeHint);
        }
    }
}
