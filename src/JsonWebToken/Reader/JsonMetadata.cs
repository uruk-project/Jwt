using System;
using System.Buffers;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading;

namespace JsonWebToken
{
    // taken from https://github.com/dotnet/runtime/blob/master/src/libraries/System.Text.Json/src/System/Text/Json/Document/JsonDocument.MetadataDb.cs
    internal struct JsonMetadata : IDisposable
    {
        private const int SizeOrLengthOffset = 4;
        private const int NumberOfRowsOffset = 8;

        internal int Length { get; private set; }
        public int Count { get; private set; }

        private byte[] _data;

        internal JsonMetadata(byte[] completeDb)
        {
            _data = completeDb;
            Length = completeDb.Length;
            Count = Length / JsonRow.Size;
        }

        internal JsonMetadata(int payloadLength)
        {
            // Assume that a token happens approximately every 12 bytes.
            // int estimatedTokens = payloadLength / 12
            // now acknowledge that the number of bytes we need per token is 12.
            // So that's just the payload length.
            //
            // Add one token's worth of data just because.
            int initialSize = JsonRow.Size + payloadLength;

            // Stick with ArrayPool's rent/return range if it looks feasible.
            // If it's wrong, we'll just grow and copy as we would if the tokens
            // were more frequent anyways.
            const int OneMegabyte = 1024 * 1024;

            if (initialSize > OneMegabyte && initialSize <= 4 * OneMegabyte)
            {
                initialSize = OneMegabyte;
            }

            _data = ArrayPool<byte>.Shared.Rent(initialSize);
            Length = 0;
            Count = 0;
        }

        public void Dispose()
        {
            byte[]? data = Interlocked.Exchange(ref _data, null!);
            if (data == null)
            {
                return;
            }

            ArrayPool<byte>.Shared.Return(data);
            Length = 0;
        }

        internal void CompleteAllocations()
        {
            if (Length > 128 && Length <= _data.Length / 2)
            {
                byte[] newRent = ArrayPool<byte>.Shared.Rent(Length);
                byte[] returnBuf = newRent;

                if (newRent.Length < _data.Length)
                {
                    Buffer.BlockCopy(_data, 0, newRent, 0, Length);
                    returnBuf = _data;
                    _data = newRent;
                }

                ArrayPool<byte>.Shared.Return(returnBuf);
            }

            Count = Length / JsonRow.Size;
        }

        internal void Append(JsonTokenType tokenType, int startLocation, int length)
        {
            if (Length >= _data.Length - JsonRow.Size)
            {
                Enlarge();
            }

            JsonRow row = new JsonRow(tokenType, startLocation, length);
#if NET8_0_OR_GREATER
            MemoryMarshal.Write(_data.AsSpan(Length), in row);
#else
            MemoryMarshal.Write(_data.AsSpan(Length), ref row);
#endif
            Length += JsonRow.Size;
        }

        private void Enlarge()
        {
            byte[] toReturn = _data;
            _data = ArrayPool<byte>.Shared.Rent(toReturn.Length * 2);
            Buffer.BlockCopy(toReturn, 0, _data, 0, toReturn.Length);

            ArrayPool<byte>.Shared.Return(toReturn);
        }

        [Conditional("DEBUG")]
        private void AssertValidIndex(int index)
        {
            Debug.Assert(index >= 0);
            Debug.Assert(index <= Length - JsonRow.Size, $"index {index} is out of bounds");
            Debug.Assert(index % JsonRow.Size == 0, $"index {index} is not at a record start position");
        }

        internal void SetLength(int index, int length)
        {
            AssertValidIndex(index);
            Debug.Assert(length >= 0);
            Span<byte> destination = _data.AsSpan(index + SizeOrLengthOffset);
#if NET8_0_OR_GREATER
            MemoryMarshal.Write(destination, in length);
#else
            MemoryMarshal.Write(destination, ref length);
#endif
        }

        internal void SetNumberOfRows(int index, int numberOfRows)
        {
            AssertValidIndex(index);
            Debug.Assert(numberOfRows >= 0 && numberOfRows <= 0x0FFFFFFF);

            Span<byte> dataPos = _data.AsSpan(index + NumberOfRowsOffset);
            int current = MemoryMarshal.Read<int>(dataPos);

            // Persist the most significant nybble
            int value = (current & unchecked((int)0xF0000000)) | numberOfRows;
#if NET8_0_OR_GREATER
            MemoryMarshal.Write(dataPos, in value);
#else
            MemoryMarshal.Write(dataPos, ref value);
#endif
        }

        internal void SetNeedUnescaping(int index)
        {
            AssertValidIndex(index);

            // The NeedEscaping bit is the most significant bit of "SizeOrLength"
            Span<byte> dataPos = _data.AsSpan(index + SizeOrLengthOffset);
            int current = MemoryMarshal.Read<int>(dataPos);

            int value = current | unchecked((int)0x80000000);
#if NET8_0_OR_GREATER
            MemoryMarshal.Write(dataPos, in value);
#else
            MemoryMarshal.Write(dataPos, ref value);
#endif
        }

        internal JsonRow Get(int index)
        {
            AssertValidIndex(index);
            return MemoryMarshal.Read<JsonRow>(_data.AsSpan(index));
        }

        internal JsonTokenType GetJsonTokenType(int index)
        {
            AssertValidIndex(index);
            uint union = MemoryMarshal.Read<uint>(_data.AsSpan(index + NumberOfRowsOffset));

            return (JsonTokenType)(union >> 28);
        }

        internal JsonMetadata Clone()
        {
            byte[] newDatabase = new byte[Length];
            _data.AsSpan(0, Length).CopyTo(newDatabase);
            return new JsonMetadata(newDatabase);
        }

        internal JsonMetadata CopySegment(int startIndex, int endIndex)
        {
            Debug.Assert(
                endIndex > startIndex,
                $"endIndex={endIndex} was at or before startIndex={startIndex}");

            AssertValidIndex(startIndex);
            Debug.Assert(endIndex <= Length);

            JsonRow start = Get(startIndex);
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

            for (int i = (length - JsonRow.Size) / sizeof(int); i >= 0; i -= JsonRow.Size / sizeof(int))
            {
                Debug.Assert(newDbInts[i] >= locationOffset);
                newDbInts[i] -= locationOffset;
            }

            return new JsonMetadata(newDatabase);
        }
    }
}