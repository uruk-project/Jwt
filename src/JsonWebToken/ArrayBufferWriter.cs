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
    public sealed class ArrayBufferWriter<T> : IBufferWriter<T>, IDisposable
    {
        private T[] _rentedBuffer;
        private int _index;

        private const int MinimumBufferSize = 256;

        /// <summary>
        /// Initializes a new instance of the <see cref="ArrayBufferWriter{T}"/> class.
        /// </summary>
        /// <param name="capacity"></param>
        public ArrayBufferWriter(int capacity = MinimumBufferSize)
        {
            if (capacity <= 0)
            {
                Errors.ThrowArgumentOutOfRange_NeedNonNegNum(ExceptionArgument.capacity);
            }

            _rentedBuffer = ArrayPool<T>.Shared.Rent(capacity);
            _index = 0;
        }

        /// <summary>
        /// Gets the output as a <see cref="Memory{T}"/>.
        /// </summary>
        public ReadOnlyMemory<T> WrittenMemory
        {
            get
            {
                CheckIfDisposed();

                return _rentedBuffer.AsMemory(0, _index);
            }
        }

        /// <summary>
        /// Gets the output as a <see cref="ReadOnlySpan{T}"/>.
        /// </summary>
        public ReadOnlySpan<T> WrittenSpan
        {
            get
            {
                CheckIfDisposed();

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
                CheckIfDisposed();

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
                CheckIfDisposed();

                return _rentedBuffer.Length;
            }
        }

        /// <summary>
        /// Clear the <see cref="ArrayBufferWriter{T}"/>. 
        /// </summary>
        public void Clear()
        {
            CheckIfDisposed();

            ClearHelper();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ClearHelper()
        {
            Debug.Assert(_rentedBuffer != null);
            _rentedBuffer.AsSpan(0, _index).Clear();
            _index = 0;
        }

        /// <summary>
        /// Advances the <see cref="ArrayBufferWriter{T}"/> of the <paramref name="count"/> indicated.
        /// </summary>
        /// <param name="count"></param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Advance(int count)
        {
            CheckIfDisposed();
            Debug.Assert(count >= 0);

            if (_index > _rentedBuffer.Length - count)
            {
                Errors.ThrowCannotAdvanceBuffer();
            }

            _index += count;
        }

        /// <summary>
        /// Returns the rented buffer back to the pool.
        /// </summary>
        public void Dispose()
        {
            if (_rentedBuffer != null)
            {
                ClearHelper();
                ArrayPool<T>.Shared.Return(_rentedBuffer);
                _rentedBuffer = null;
            }
        }

        [Conditional("DEBUG")]
        private void CheckIfDisposed()
        {
            if (_rentedBuffer == null)
            {
                Errors.ThrowObjectDisposed(typeof(ArrayBufferWriter<T>));
            }
        }

        /// <inheritsdoc />
        public Span<T> GetSpan(int sizeHint = 0)
        {
            CheckIfDisposed();

            CheckAndResizeBuffer(sizeHint);
            return _rentedBuffer.AsSpan(_index);
        }


        /// <inheritsdoc />
        public Memory<T> GetMemory(int sizeHint = 0)
        {
            CheckIfDisposed();

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

                T[] oldBuffer = _rentedBuffer;

                _rentedBuffer = ArrayPool<T>.Shared.Rent(newSize);

                Debug.Assert(oldBuffer.Length >= _index);
                Debug.Assert(_rentedBuffer.Length >= _index);

                Span<T> previousBuffer = oldBuffer.AsSpan(0, _index);
                previousBuffer.CopyTo(_rentedBuffer);
                previousBuffer.Clear();
                ArrayPool<T>.Shared.Return(oldBuffer);
            }

            Debug.Assert(_rentedBuffer.Length - _index > 0);
            Debug.Assert(_rentedBuffer.Length - _index >= sizeHint);
        }
    }

    /// <summary>
    /// Reprensents an implementation of <see cref="IBufferWriter{T}" /> where the memory owner is a <see cref="ArrayPool{T}"/>.
    /// </summary>
    public unsafe class UnmanagedBufferWriter<T> : IBufferWriter<T>, IDisposable
    {
        private IntPtr _rentedBuffer;
        private int _index;
        private int _capacity;

        private const int MinimumBufferSize = 256;

        /// <summary>
        /// Initializes a new instance of the <see cref="UnmanagedBufferWriter{T}"/> class.
        /// </summary>
        /// <param name="capacity"></param>
        public UnmanagedBufferWriter(int capacity = MinimumBufferSize)
        {
            if (capacity <= 0)
            {
                Errors.ThrowArgumentOutOfRange_NeedNonNegNum(ExceptionArgument.capacity);
            }

            _capacity = Marshal.SizeOf(typeof(T)) * capacity;
            _rentedBuffer = Marshal.AllocHGlobal(_capacity);
            _index = 0;
        }

        /// <summary>
        /// Gets the output as a <see cref="ReadOnlySpan{T}"/>.
        /// </summary>
        public ReadOnlySpan<T> WrittenSpan
        {
            get
            {
                CheckIfDisposed();

                return new ReadOnlySpan<T>(_rentedBuffer.ToPointer(), _index);
            }
        }

        /// <summary>
        /// Gets the bytes written.
        /// </summary>
        public int WrittenCount
        {
            get
            {
                CheckIfDisposed();

                return _index;
            }
        }

        /// <summary>
        /// Clear the <see cref="UnmanagedBufferWriter{T}"/>. 
        /// </summary>
        public void Clear()
        {
            CheckIfDisposed();

            ClearHelper();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ClearHelper()
        {
            Debug.Assert(_rentedBuffer != null);
            new Span<T>(_rentedBuffer.ToPointer(), _index).Clear();
            _index = 0;
        }

        /// <summary>
        /// Advances the <see cref="UnmanagedBufferWriter{T}"/> of the <paramref name="count"/> indicated.
        /// </summary>
        /// <param name="count"></param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Advance(int count)
        {
            CheckIfDisposed();

            if (count < 0)
            {
                Errors.ThrowMustBeGreaterOrEqualToZero(ExceptionArgument.count, count);
            }

            if (_index > _capacity - count)
            {
                Errors.ThrowCannotAdvanceBuffer();
            }

            _index += count;
        }

        /// <summary>
        /// Returns the rented buffer back to the pool.
        /// </summary>
        public void Dispose()
        {
            if (_rentedBuffer != IntPtr.Zero)
            {
                ClearHelper();
                Marshal.FreeHGlobal(_rentedBuffer);
                _index = 0;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void CheckIfDisposed()
        {
            if (_rentedBuffer == IntPtr.Zero)
            {
                Errors.ThrowObjectDisposed(typeof(UnmanagedBufferWriter<T>));
            }
        }

        /// <inheritsdoc />
        public Memory<T> GetMemory(int sizeHint = 0)
        {
            throw new NotImplementedException();
        }

        /// <inheritsdoc />
        public Span<T> GetSpan(int sizeHint = 0)
        {
            CheckIfDisposed();
            CheckAndResizeBuffer(sizeHint);
            return new Span<T>(_rentedBuffer.ToPointer(), _capacity).Slice(_index, sizeHint);
        }

        private void CheckAndResizeBuffer(int sizeHint)
        {
            Debug.Assert(_rentedBuffer != IntPtr.Zero);
            if (sizeHint < 0)
            {
                Errors.ThrowArgument(nameof(sizeHint));
            }

            if (sizeHint == 0)
            {
                sizeHint = MinimumBufferSize;
            }

            int availableSpace = _capacity - _index;
            if (sizeHint > availableSpace)
            {
                int growBy = Math.Max(sizeHint, _capacity);

                int newSize = checked(_capacity + growBy);

                var oldBuffer = _rentedBuffer;

                _rentedBuffer = Marshal.AllocHGlobal(newSize);

                //Debug.Assert(oldBuffer.Length >= _written);
                Debug.Assert(newSize >= _index);

                Buffer.MemoryCopy(oldBuffer.ToPointer(), _rentedBuffer.ToPointer(), newSize, _index);
                new Span<T>(oldBuffer.ToPointer(), _capacity).Clear();
                _capacity = newSize;
                Marshal.FreeHGlobal(oldBuffer);
            }

            Debug.Assert(_capacity - _index > 0);
            Debug.Assert(_capacity - _index >= sizeHint);
        }
    }
}
