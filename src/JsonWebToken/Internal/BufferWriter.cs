// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.
using System;
using System.Buffers;
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace JsonWebToken
{
    internal class BufferWriter : IBufferWriter<byte>, IDisposable
    {
        internal const int SegmentPoolSize = 16;

        private readonly MemoryPool<byte> _pool;
        private readonly int _minimumSegmentSize;

        private readonly BufferSegment[] _bufferSegmentPool;

        private int _pooledSegmentCount;

        // The commit head which is the extent of the bytes available to the IPipelineReader to consume
        private BufferSegment _head;

        // The write head which is the extent of the IPipelineWriter's written bytes
        private BufferSegment _tail;
        private bool _disposed;

        public BufferWriter()
        {
            _bufferSegmentPool = new BufferSegment[SegmentPoolSize];

            _pool = MemoryPool<byte>.Shared;
            _minimumSegmentSize = 512;
        }

        public Memory<byte> GetMemory(int sizeHint)
        {
            if (sizeHint < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(sizeHint));
            }

            AllocateWriteSegment(sizeHint);

            // Slice the AvailableMemory to the WritableBytes size
            int end = _tail.End;
            Memory<byte> availableMemory = _tail.AvailableMemory;
            availableMemory = availableMemory.Slice(end);
            return availableMemory;
        }

        public Span<byte> GetSpan(int sizeHint)
        {
            if (sizeHint < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(sizeHint));
            }

            AllocateWriteSegment(sizeHint);

            // Slice the AvailableMemory to the WritableBytes size
            int end = _tail.End;
            Span<byte> availableSpan = _tail.AvailableMemory.Span;
            availableSpan = availableSpan.Slice(end);
            return availableSpan;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Advance(int bytesWritten)
        {
            if (_tail == null)
            {
                throw new InvalidOperationException();
                //ThrowHelper.ThrowInvalidOperationException_NotWritingNoAlloc();
            }

            if (bytesWritten >= 0)
            {
                Debug.Assert(!_tail.ReadOnly);
                Debug.Assert(_tail.Next == null);

                Memory<byte> buffer = _tail.AvailableMemory;

                if (_tail.End > buffer.Length - bytesWritten)
                {
                    throw new InvalidOperationException();
                    //ThrowHelper.ThrowInvalidOperationException_AdvancingPastBufferSize();
                }

                // if bytesWritten is zero, these do nothing
                _tail.End += bytesWritten;
            }
            else
            {
                throw new ArgumentOutOfRangeException(nameof(bytesWritten));
            }
        }

        private void AllocateWriteSegment(int sizeHint)
        {
            BufferSegment segment;
            if (_tail != null)
            {
                segment = _tail;

                int bytesLeftInBuffer = segment.WritableBytes;

                // If inadequate bytes left or if the segment is readonly
                if (bytesLeftInBuffer == 0 || bytesLeftInBuffer < sizeHint || segment.ReadOnly)
                {
                    BufferSegment nextSegment = CreateSegment();
                    nextSegment.SetMemory(_pool.Rent(GetSegmentSize(sizeHint)));

                    segment.SetNext(nextSegment);

                    _tail = nextSegment;
                }
            }
            else
            {
                if (_head != null && !_head.ReadOnly)
                {
                    // Try to return the tail so the calling code can append to it
                    int remaining = _head.WritableBytes;

                    if (sizeHint <= remaining && remaining > 0)
                    {
                        // Free tail space of the right amount, use that
                        segment = _head;

                        // Set write head to assigned segment
                        _tail = segment;
                        return;
                    }
                }

                // No free tail space, allocate a new segment
                segment = CreateSegment();
                segment.SetMemory(_pool.Rent(GetSegmentSize(sizeHint)));

                if (_head == null)
                {
                    // No previous writes have occurred
                    _head = segment;
                }
                else if (segment != _head && _head.Next == null)
                {
                    // Append the segment to the commit head if writes have been committed
                    // and it isn't the same segment (unused tail space)
                    _head.SetNext(segment);
                }

                // Set write head to assigned segment
                _tail = segment;
            }
        }

        public ReadOnlySequence<byte> OutputAsSequence
        {
            get
            {
                return new ReadOnlySequence<byte>(_head, 0, _tail, _tail.End);
            }
        }

        private int GetSegmentSize(int sizeHint)
        {
            // First we need to handle case where hint is smaller than minimum segment size
            sizeHint = Math.Max(_minimumSegmentSize, sizeHint);
            // After that adjust it to fit into pools max buffer size
            var adjustedToMaximumSize = Math.Min(_pool.MaxBufferSize, sizeHint);
            return adjustedToMaximumSize;
        }

        private BufferSegment CreateSegment()
        {
            if (_pooledSegmentCount > 0)
            {
                _pooledSegmentCount--;
                return _bufferSegmentPool[_pooledSegmentCount];
            }

            return new BufferSegment();
        }

        public void Reset()
        {
            _head = null;
            _tail = null;
            _pooledSegmentCount = 0;
        }

        // Returns the rented buffer back to the pool
        public void Dispose()
        {
            if (!_disposed && _pooledSegmentCount != 0)
            {
                _disposed = true;
                BufferSegment segment = _head;
                while (segment != null)
                {
                    segment.ResetMemory();
                    segment = segment.NextSegment;
                }

                Reset();
            }
        }
    }

    internal sealed class BufferSegment : ReadOnlySequenceSegment<byte>
    {
        private IMemoryOwner<byte> _memoryOwner;
        private BufferSegment _next;
        private int _end;

        /// <summary>
        /// The Start represents the offset into AvailableMemory where the range of "active" bytes begins. At the point when the block is leased
        /// the Start is guaranteed to be equal to 0. The value of Start may be assigned anywhere between 0 and
        /// AvailableMemory.Length, and must be equal to or less than End.
        /// </summary>
        public int Start { get; private set; }

        /// <summary>
        /// The End represents the offset into AvailableMemory where the range of "active" bytes ends. At the point when the block is leased
        /// the End is guaranteed to be equal to Start. The value of Start may be assigned anywhere between 0 and
        /// Buffer.Length, and must be equal to or less than End.
        /// </summary>
        public int End
        {
            get => _end;
            set
            {
                Debug.Assert(value - Start <= AvailableMemory.Length);

                _end = value;
                Memory = AvailableMemory.Slice(Start, _end - Start);
            }
        }

        /// <summary>
        /// Reference to the next block of data when the overall "active" bytes spans multiple blocks. At the point when the block is
        /// leased Next is guaranteed to be null. Start, End, and Next are used together in order to create a linked-list of discontiguous
        /// working memory. The "active" memory is grown when bytes are copied in, End is increased, and Next is assigned. The "active"
        /// memory is shrunk when bytes are consumed, Start is increased, and blocks are returned to the pool.
        /// </summary>
        public BufferSegment NextSegment
        {
            get => _next;
            set
            {
                _next = value;
                Next = value;
            }
        }

        public void SetMemory(IMemoryOwner<byte> memoryOwner)
        {
            SetMemory(memoryOwner, 0, 0);
        }

        public void SetMemory(IMemoryOwner<byte> memoryOwner, int start, int end, bool readOnly = false)
        {
            _memoryOwner = memoryOwner;

            AvailableMemory = _memoryOwner.Memory;

            ReadOnly = readOnly;
            RunningIndex = 0;
            Start = start;
            End = end;
            NextSegment = null;
        }

        public void ResetMemory()
        {
            _memoryOwner.Dispose();
            _memoryOwner = null;
            AvailableMemory = default;
        }

        public IMemoryOwner<byte> MemoryOwner => _memoryOwner;

        public Memory<byte> AvailableMemory { get; private set; }

        public int Length => End - Start;

        /// <summary>
        /// If true, data should not be written into the backing block after the End offset. Data between start and end should never be modified
        /// since this would break cloning.
        /// </summary>
        public bool ReadOnly { get; private set; }

        /// <summary>
        /// The amount of writable bytes in this segment. It is the amount of bytes between Length and End
        /// </summary>
        public int WritableBytes
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get => AvailableMemory.Length - End;
        }

        public void SetNext(BufferSegment segment)
        {
            Debug.Assert(segment != null);
            Debug.Assert(Next == null);

            NextSegment = segment;

            segment = this;

            while (segment.Next != null)
            {
                segment.NextSegment.RunningIndex = segment.RunningIndex + segment.Length;
                segment = segment.NextSegment;
            }
        }
    }
}