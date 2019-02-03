using System;
using System.Buffers;
using System.Diagnostics;

namespace JsonWebToken
{
    /// <summary>
    /// Reprensents an impelemntation of <see cref="IBufferWriter{T}" /> where the memory owner is a <see cref="ArrayPool{T}"/>.
    /// </summary>
    public class ArrayBufferWriter : IBufferWriter<byte>, IDisposable
    {
        private byte[] _rentedBuffer;
        private int _written;

        private const int MinimumBufferSize = 256;

        /// <summary>
        /// Initializes a new instance of the <see cref="ArrayBufferWriter"/> class.
        /// </summary>
        /// <param name="initialCapacity"></param>
        public ArrayBufferWriter(int initialCapacity = MinimumBufferSize)
        {
            if (initialCapacity <= 0)
            {
                throw new ArgumentException(nameof(initialCapacity));
            }

            _rentedBuffer = ArrayPool<byte>.Shared.Rent(initialCapacity);
            _written = 0;
        }

        /// <summary>
        /// Gets the output as a <see cref="Memory{T}"/>.
        /// </summary>
        public Memory<byte> OutputAsMemory
        {
            get
            {
                CheckIfDisposed();

                return _rentedBuffer.AsMemory(0, _written);
            }
        }

        /// <summary>
        /// Gets the output as a <see cref="Span{T}"/>.
        /// </summary>
        public Span<byte> OutputAsSpan
        {
            get
            {
                CheckIfDisposed();

                return _rentedBuffer.AsSpan(0, _written);
            }
        }

        /// <summary>
        /// Gets the bytes written.
        /// </summary>
        public int BytesWritten
        {
            get
            {
                CheckIfDisposed();

                return _written;
            }
        }

        /// <summary>
        /// Clear the <see cref="ArrayBufferWriter"/>. 
        /// </summary>
        public void Clear()
        {
            CheckIfDisposed();

            ClearHelper();
        }

        private void ClearHelper()
        {
            _rentedBuffer.AsSpan(0, _written).Clear();
            _written = 0;
        }

        /// <summary>
        /// Advances the <see cref="ArrayBufferWriter"/> of the <paramref name="count"/> indicated.
        /// </summary>
        /// <param name="count"></param>
        public void Advance(int count)
        {
            CheckIfDisposed();

            if (count < 0)
            {
                throw new ArgumentException(nameof(count));
            }

            if (_written > _rentedBuffer.Length - count)
            {
                throw new InvalidOperationException("Cannot advance past the end of the buffer.");
            }

            _written += count;
        }

        /// <summary>
        /// Returns the rented buffer back to the pool.
        /// </summary>
        public void Dispose()
        {
            if (_rentedBuffer != null)
            {
                ArrayPool<byte>.Shared.Return(_rentedBuffer, clearArray: true);
                _rentedBuffer = null;
                _written = 0;
            }
        }

        private void CheckIfDisposed()
        {
            if (_rentedBuffer == null)
            {
                throw new ObjectDisposedException(nameof(ArrayBufferWriter));
            }
        }

        /// <inheritsdoc />
        public Memory<byte> GetMemory(int sizeHint = 0)
        {
            CheckIfDisposed();

            if (sizeHint < 0)
            {
                throw new ArgumentException(nameof(sizeHint));
            }

            CheckAndResizeBuffer(sizeHint);
            return _rentedBuffer.AsMemory(_written);
        }

        /// <inheritsdoc />
        public Span<byte> GetSpan(int sizeHint = 0)
        {
            CheckIfDisposed();

            if (sizeHint < 0)
            {
                throw new ArgumentException(nameof(sizeHint));
            }

            CheckAndResizeBuffer(sizeHint);
            return _rentedBuffer.AsSpan(_written);
        }

        private void CheckAndResizeBuffer(int sizeHint)
        {
            Debug.Assert(sizeHint >= 0);
            if (sizeHint == 0)
            {
                sizeHint = MinimumBufferSize;
            }

            int availableSpace = _rentedBuffer.Length - _written;
            if (sizeHint > availableSpace)
            {
                int growBy = sizeHint > _rentedBuffer.Length ? sizeHint : _rentedBuffer.Length;

                int newSize = checked(_rentedBuffer.Length + growBy);

                byte[] oldBuffer = _rentedBuffer;

                _rentedBuffer = ArrayPool<byte>.Shared.Rent(newSize);

                Debug.Assert(oldBuffer.Length >= _written);
                Debug.Assert(_rentedBuffer.Length >= _written);

                oldBuffer.AsSpan(0, _written).CopyTo(_rentedBuffer);
                ArrayPool<byte>.Shared.Return(oldBuffer, clearArray: true);
            }

            Debug.Assert(_rentedBuffer.Length - _written > 0);
            Debug.Assert(_rentedBuffer.Length - _written >= sizeHint);
        }
    }

}
