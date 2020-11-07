using System;
using System.Buffers;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading;

namespace JsonWebToken
{
    internal struct JwtObjectMetadataDb : IDisposable
    {
        internal int Length { get; private set; }
        public int Count { get; private set; }

        private byte[] _data;

        internal JwtObjectMetadataDb(byte[] completeDb)
        {
            _data = completeDb;
            Length = completeDb.Length;
            Count = completeDb.Length / JwtObjectRow.Size;
        }

        internal JwtObjectMetadataDb(int initialSize)
        {
            _data = ArrayPool<byte>.Shared.Rent(initialSize);
            Length = 0;
            Count = 0;
        }

        internal JwtObjectMetadataDb(JwtObjectMetadataDb source, bool useArrayPools)
        {
            Length = source.Length;
            Count = source.Count;

            if (useArrayPools)
            {
                _data = ArrayPool<byte>.Shared.Rent(Length);
                source._data.AsSpan(0, Length).CopyTo(_data);
            }
            else
            {
                _data = source._data.AsSpan(0, Length).ToArray();
            }
        }

        public void Dispose()
        {
            byte[]? data = Interlocked.Exchange(ref _data, null!);
            if (data == null)
            {
                return;
            }

            // The data in this rented buffer only conveys the positions and
            // lengths of tokens in a document, but no content; so it does not
            // need to be cleared.
            ArrayPool<byte>.Shared.Return(data);
            Length = 0;
        }

        internal void TrimExcess()
        {
            // There's a chance that the size we have is the size we'd get for this
            // amount of usage (particularly if Enlarge ever got called); and there's
            // the small copy-cost associated with trimming anyways. "Is half-empty" is
            // just a rough metric for "is trimming worth it?".
            if (Length <= _data.Length / 2)
            {
                byte[] newRent = ArrayPool<byte>.Shared.Rent(Length);
                byte[] returnBuf = newRent;

                if (newRent.Length < _data.Length)
                {
                    Buffer.BlockCopy(_data, 0, newRent, 0, Length);
                    returnBuf = _data;
                    _data = newRent;
                }

                // The data in this rented buffer only conveys the positions and
                // lengths of tokens in a document, but no content; so it does not
                // need to be cleared.
                ArrayPool<byte>.Shared.Return(returnBuf);
            }

            Count = Length / JwtObjectRow.Size;
        }

        internal void Append(JsonTokenType tokenType, int startLocation, int propertyLength, int valueLength)
        {
            if (Length >= _data.Length - JwtObjectRow.Size)
            {
                Enlarge();
            }

            JwtObjectRow row = new JwtObjectRow(tokenType, startLocation, propertyLength, valueLength);
            MemoryMarshal.Write(_data.AsSpan(Length), ref row);
            Length += JwtObjectRow.Size;
        }

        private void Enlarge()
        {
            byte[] toReturn = _data;
            _data = ArrayPool<byte>.Shared.Rent(toReturn.Length * 2);
            Buffer.BlockCopy(toReturn, 0, _data, 0, toReturn.Length);

            // The data in this rented buffer only conveys the positions and
            // lengths of tokens in a document, but no content; so it does not
            // need to be cleared.
            ArrayPool<byte>.Shared.Return(toReturn);
        }

        [Conditional("DEBUG")]
        private void AssertValidIndex(int index)
        {
            Debug.Assert(index >= 0);
            Debug.Assert(index <= Length - JwtObjectRow.Size, $"index {index} is out of bounds");
            Debug.Assert(index % JwtObjectRow.Size == 0, $"index {index} is not at a record start position");
        }

        internal JwtObjectRow Get(int index)
        {
            AssertValidIndex(index);
            return MemoryMarshal.Read<JwtObjectRow>(_data.AsSpan(index));
        }

        internal JwtTokenType GetJwtTokenType(int index)
        {
            AssertValidIndex(index);
            uint union = MemoryMarshal.Read<uint>(_data.AsSpan(index));

            return (JwtTokenType)(union >> 28);
        }

        internal JwtObjectMetadataDb Clone()
        {
            byte[] newDatabase = new byte[Length];
            _data.AsSpan(0, Length).CopyTo(newDatabase);
            return new JwtObjectMetadataDb(newDatabase);
        }

        internal JwtObjectMetadataDb CopySegment(int startIndex, int endIndex)
        {
            Debug.Assert(
                endIndex > startIndex,
                $"endIndex={endIndex} was at or before startIndex={startIndex}");

            AssertValidIndex(startIndex);
            Debug.Assert(endIndex <= Length);

            JwtObjectRow start = Get(startIndex);
            int length = endIndex - startIndex;

            byte[] newDatabase = new byte[length];
            _data.AsSpan(startIndex, length).CopyTo(newDatabase);

            Span<int> newDbInts = MemoryMarshal.Cast<byte, int>(newDatabase);
            int locationOffset = newDbInts[0];

            // Need to nudge one forward to account for the hidden quote on the string.
            if (start.TokenType == JsonTokenType.String)
            {
                locationOffset--;
            }

            for (int i = (length - JwtObjectRow.Size) / sizeof(int); i >= 0; i -= JwtObjectRow.Size / sizeof(int))
            {
                Debug.Assert(newDbInts[i] >= locationOffset);
                newDbInts[i] -= locationOffset;
            }

            return new JwtObjectMetadataDb(newDatabase);
        }
    }
}