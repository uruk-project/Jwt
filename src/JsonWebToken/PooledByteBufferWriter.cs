// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.Diagnostics;
using System.Runtime.CompilerServices;

#nullable disable

namespace JsonWebToken
{
    /// <summary>
    /// Represents an implementation of <see cref="IBufferWriter{T}" /> where the memory owner is a <see cref="ArrayPool{T}" /> of bytes.
    /// </summary>
    public sealed class PooledByteBufferWriter : IBufferWriter<byte>, IDisposable
    {
        private byte[] _rentedBuffer;
        private int _index;

        private const int MinimumBufferSize = 256;

        /// <summary>
        /// Initializes a new instance of the <see cref="PooledByteBufferWriter"/> class.
        /// </summary>
        /// <param name="initialCapacity "></param>
        public PooledByteBufferWriter(int initialCapacity = MinimumBufferSize)
        {
            Debug.Assert(initialCapacity > 0);

            _rentedBuffer = ArrayPool<byte>.Shared.Rent(initialCapacity);
            _index = 0;
        }

#if NETSTANDARD2_0
        /// <summary>
        /// Gets the current index.
        /// </summary>
        public int Index => _index;

        /// <summary>
        /// Gets the output as a <see cref="byte" /> array.
        /// </summary>
        public byte[] Buffer
        {
            get
            {
                return _rentedBuffer;
            }
        }
#endif

        /// <summary>
        /// Gets the output as a <see cref="Memory{T}"/>.
        /// </summary>
        public ReadOnlyMemory<byte> WrittenMemory
        {
            get
            {
                Debug.Assert(_rentedBuffer != null);
                Debug.Assert(_index <= _rentedBuffer.Length);
                return _rentedBuffer.AsMemory(0, _index);
            }
        }

        /// <summary>
        /// Gets the output as a <see cref="ReadOnlySpan{T}"/>.
        /// </summary>
        public ReadOnlySpan<byte> WrittenSpan
        {
            get
            {
                Debug.Assert(_rentedBuffer != null);
                Debug.Assert(_index <= _rentedBuffer.Length);
                return _rentedBuffer.AsSpan(0, _index);
            }
        }

        /// <summary>
        /// Gets the bytes written.
        /// </summary>
        public int WrittenCount
        {
            get
            {
                Debug.Assert(_rentedBuffer != null);
                return _index;
            }
        }

        /// <summary>
        /// Gets the capacity.
        /// </summary>
        public int Capacity
        {
            get
            {
                Debug.Assert(_rentedBuffer != null);
                return _rentedBuffer.Length;
            }
        }

        /// <summary>
        /// Clear the <see cref="PooledByteBufferWriter"/>. 
        /// </summary>
        public void Clear()
        {
            ClearHelper();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ClearHelper()
        {
            Debug.Assert(_rentedBuffer != null);
            Debug.Assert(_index <= _rentedBuffer.Length);
            _rentedBuffer.AsSpan(0, _index).Clear();
            _index = 0;
        }

        /// <summary>
        /// Advances the <see cref="PooledByteBufferWriter"/> of the <paramref name="count"/> indicated.
        /// </summary>
        /// <param name="count"></param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Advance(int count)
        {
            Debug.Assert(_rentedBuffer != null);
            Debug.Assert(count >= 0);
            Debug.Assert(_index <= _rentedBuffer.Length - count);
            _index += count;
        }

        /// <summary>
        /// Returns the rented buffer back to the pool.
        /// </summary>
        public void Dispose()
        {
            ClearHelper();
            ArrayPool<byte>.Shared.Return(_rentedBuffer);
        }

        /// <inheritsdoc />
        public Span<byte> GetSpan(int sizeHint = 0)
        {
            CheckAndResizeBuffer(sizeHint);
            return _rentedBuffer.AsSpan(_index);
        }

        /// <inheritsdoc />
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

            int bufferLength = _rentedBuffer.Length;
            int availableSpace = bufferLength - _index;
            if (sizeHint > availableSpace)
            {
                int growBy = Math.Max(sizeHint, bufferLength);
                int newSize = checked(bufferLength + growBy);

                byte[] oldBuffer = _rentedBuffer;

                _rentedBuffer = ArrayPool<byte>.Shared.Rent(newSize);

                Debug.Assert(oldBuffer.Length >= _index);
                Debug.Assert(_rentedBuffer.Length >= _index);

                Span<byte> previousBuffer = oldBuffer.AsSpan(0, _index);
                previousBuffer.CopyTo(_rentedBuffer);
                ArrayPool<byte>.Shared.Return(oldBuffer, true);
            }

            Debug.Assert(_rentedBuffer.Length - _index > 0);
            Debug.Assert(_rentedBuffer.Length - _index >= sizeHint);
        }
    }
}
