using System;
using System.Buffers;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace JsonWebToken
{
    /// <summary>
    /// Reprensents an implementation of <see cref="IBufferWriter{T}" /> where the memory owner is a <see cref="ArrayPool{T}"/>.
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
        /// Gets the output as a <see cref="Span{T}"/>.
        /// </summary>
        public ReadOnlySequence<byte> OutputAsSequence
        {
            get
            {
                CheckIfDisposed();

                return new ReadOnlySequence<byte>(_rentedBuffer, 0, _written);
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

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ClearHelper()
        {
            _rentedBuffer.AsSpan(0, _written).Clear();
            _written = 0;
        }

        /// <summary>
        /// Advances the <see cref="ArrayBufferWriter"/> of the <paramref name="count"/> indicated.
        /// </summary>
        /// <param name="count"></param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Advance(int count)
        {
            CheckIfDisposed();

            if (count < 0)
            {
                Errors.ThrowMustBeGreaterOrEqualToZero(nameof(count), count);
            }

            if (_written > _rentedBuffer.Length - count)
            {
                Errors.ThrowCannotAdvanceBuffer();
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

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void CheckIfDisposed()
        {
            if (_rentedBuffer == null)
            {
                Errors.ThrowObjectDisposed(typeof(ArrayBufferWriter));
            }
        }

        /// <inheritsdoc />
        public Memory<byte> GetMemory(int sizeHint = 0)
        {
            CheckIfDisposed();

            if (sizeHint < 0)
            {
                Errors.ThrowArgument(nameof(sizeHint));
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
                Errors.ThrowArgument(nameof(sizeHint));
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

    /// <summary>
    /// Reprensents an implementation of <see cref="IBufferWriter{T}" /> where the memory owner is a <see cref="ArrayPool{T}"/>.
    /// </summary>
    public unsafe class UnmanagedBufferWriter : IBufferWriter<byte>, IDisposable
    {
        private IntPtr _rentedBuffer;
        private int _written;
        private int _capacity;

        private const int MinimumBufferSize = 256;

        /// <summary>
        /// Initializes a new instance of the <see cref="ArrayBufferWriter"/> class.
        /// </summary>
        /// <param name="initialCapacity"></param>
        public UnmanagedBufferWriter(int initialCapacity = MinimumBufferSize)
        {
            if (initialCapacity <= 0)
            {
                throw new ArgumentException(nameof(initialCapacity));
            }

            _capacity = Marshal.SizeOf(typeof(byte)) * initialCapacity;
            _rentedBuffer = Marshal.AllocHGlobal(_capacity);
            _written = 0;
        }

        /// <summary>
        /// Gets the output as a <see cref="Span{T}"/>.
        /// </summary>
        public Span<byte> OutputAsSpan
        {
            get
            {
                CheckIfDisposed();

                return new Span<byte>(_rentedBuffer.ToPointer(), _written);
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

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ClearHelper()
        {
            OutputAsSpan.Clear();
            _written = 0;
        }

        /// <summary>
        /// Advances the <see cref="ArrayBufferWriter"/> of the <paramref name="count"/> indicated.
        /// </summary>
        /// <param name="count"></param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Advance(int count)
        {
            CheckIfDisposed();

            if (count < 0)
            {
                Errors.ThrowMustBeGreaterOrEqualToZero(nameof(count), count);
            }

            if (_written > _capacity - count)
            {
                Errors.ThrowCannotAdvanceBuffer();
            }

            _written += count;
        }

        /// <summary>
        /// Returns the rented buffer back to the pool.
        /// </summary>
        public void Dispose()
        {
            if (_rentedBuffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(_rentedBuffer);
                _written = 0;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void CheckIfDisposed()
        {
            if (_rentedBuffer == IntPtr.Zero)
            {
                Errors.ThrowObjectDisposed(typeof(ArrayBufferWriter));
            }
        }

        /// <inheritsdoc />
        public Memory<byte> GetMemory(int sizeHint = 0)
        {
            throw new NotImplementedException();
        }

        /// <inheritsdoc />
        public Span<byte> GetSpan(int sizeHint = 0)
        {
            CheckIfDisposed();

            if (sizeHint < 0)
            {
                Errors.ThrowArgument(nameof(sizeHint));
            }

            CheckAndResizeBuffer(sizeHint);
            return new Span<byte>(_rentedBuffer.ToPointer(), _capacity).Slice(_written, sizeHint);
        }

        private void CheckAndResizeBuffer(int sizeHint)
        {
            Debug.Assert(sizeHint >= 0);
            if (sizeHint == 0)
            {
                sizeHint = MinimumBufferSize;
            }

            int availableSpace = _capacity - _written;
            if (sizeHint > availableSpace)
            {
                int growBy = sizeHint > _capacity ? sizeHint : _capacity;

                int newSize = checked(_capacity + growBy);

                var oldBuffer = _rentedBuffer;

                _rentedBuffer = Marshal.AllocHGlobal(newSize);

                //Debug.Assert(oldBuffer.Length >= _written);
                Debug.Assert(newSize >= _written);

                new Span<byte>(oldBuffer.ToPointer(), _capacity).CopyTo(new Span<byte>(_rentedBuffer.ToPointer(), newSize));
                _capacity = newSize;
                Marshal.FreeHGlobal(oldBuffer);
            }

            Debug.Assert(_capacity - _written > 0);
            Debug.Assert(_capacity - _written >= sizeHint);
        }
    }

}
