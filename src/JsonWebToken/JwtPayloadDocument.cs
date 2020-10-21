// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.Data;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading;
using JsonWebToken.Internal;

namespace JsonWebToken
{
    /// <summary>
    /// Represents the claims contained in the JWT.
    /// </summary>
    public sealed partial class JwtPayloadDocumentOld : IDisposable
    {
        private JsonDocument _inner;
        private readonly JsonElement _rooElement;

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtPayload"/> class.
        /// </summary>
        /// <param name="inner"></param>
        public JwtPayloadDocumentOld(JsonDocument inner)
        {
            _inner = inner;
            _rooElement = inner.RootElement;
        }

        /// <summary>
        /// Gets the 'aud' claim as a list of strings.
        /// </summary>
        public string[]? Aud
        {
            get => _rooElement.TryGetProperty(Claims.AudUtf8, out var property) ? property.EnumerateArray().Select(e => e.GetString()!).ToArray() : null;
        }

        /// <summary>
        /// Gets the 'expiration time' claim.
        /// </summary>
        public long? Exp
        {
            get => _rooElement.TryGetProperty(Claims.ExpUtf8, out var property) ? property.GetInt64() : default;
        }

        /// <summary>
        /// Gets the 'JWT ID' claim.
        /// </summary>
        public string? Jti
        {
            get => _rooElement.TryGetProperty(Claims.JtiUtf8, out var property) ? property.GetString() : default;
        }

        /// <summary>
        /// Gets the 'issued at' claim.
        /// </summary>
        public long? Iat
        {
            get => _rooElement.TryGetProperty(Claims.IatUtf8, out var property) ? property.GetInt64() : default;
        }

        /// <summary>
        /// Gets the 'issuer' claim.
        /// </summary>
        public string? Iss
        {
            get => _rooElement.TryGetProperty(Claims.IssUtf8, out var property) ? property.GetString() : default;
        }

        /// <summary>
        /// Gets the 'not before' claim.
        /// </summary>
        public long? Nbf
        {
            get => _rooElement.TryGetProperty(Claims.NbfUtf8, out var property) ? property.GetInt64() : default;
        }

        /// <summary>
        /// Gets the 'subject' claim.
        /// </summary>
        public string? Sub
        {
            get => _rooElement.TryGetProperty(Claims.SubUtf8, out var property) ? property.GetString() : default;
        }

        /// <summary>
        /// Determines whether the <see cref="JwtPayload"/> contains the specified key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public bool ContainsKey(string key)
        {
            return ContainsKey(Utf8.GetBytes(key));
        }

        /// <summary>
        /// Determines whether the <see cref="JwtPayload"/> contains the specified key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public bool ContainsKey(ReadOnlySpan<byte> key)
        {
            return _rooElement.TryGetProperty(key, out _);
        }

        /// <summary>
        /// Gets the value associated with the specified key.
        /// </summary>
        public bool TryGetProperty(ReadOnlySpan<byte> key, [NotNullWhen(true)] out JsonElement value)
        {
            return _rooElement.TryGetProperty(key, out value);
        }

        /// <summary>
        /// Gets the value associated with the specified key.
        /// </summary>
        public bool TryGetProperty(string key, out JsonElement value)
        {
            return _rooElement.TryGetProperty(key, out value);
        }

        /// <inheritsdoc />
        public override string ToString()
        {
            using var bufferWriter = new PooledByteBufferWriter();
            using (var writer = new Utf8JsonWriter(bufferWriter, new JsonWriterOptions { Indented = true }))
            {
                _inner.WriteTo(writer);
                //writer.WriteStartObject();
                //writer.WriteEndObject();
            }

            var input = bufferWriter.WrittenSpan;
            return Utf8.GetString(input);
        }

        public void Dispose()
        {
            _inner.Dispose();
        }
    }


    public sealed partial class JwtPayloadDocumentOld
    {
        // SizeOrLength - offset - 0 - size - 4
        // NumberOfRows - offset - 4 - size - 4
        [StructLayout(LayoutKind.Sequential)]
        private struct StackRow
        {
            internal const int Size = 8;

            internal int SizeOrLength;
            internal int NumberOfRows;

            internal StackRow(int sizeOrLength = 0, int numberOfRows = -1)
            {
                Debug.Assert(sizeOrLength >= 0);
                Debug.Assert(numberOfRows >= -1);

                SizeOrLength = sizeOrLength;
                NumberOfRows = numberOfRows;
            }
        }
    }

    public sealed partial class JwtPayloadDocumentOld
    {
        private struct StackRowStack : IDisposable
        {
            private byte[] _rentedBuffer;
            private int _topOfStack;

            internal StackRowStack(int initialSize)
            {
                _rentedBuffer = ArrayPool<byte>.Shared.Rent(initialSize);
                _topOfStack = _rentedBuffer.Length;
            }

            public void Dispose()
            {
                byte[] toReturn = _rentedBuffer;
                _rentedBuffer = null!;
                _topOfStack = 0;

                if (toReturn != null)
                {
                    // The data in this rented buffer only conveys the positions and
                    // lengths of tokens in a document, but no content; so it does not
                    // need to be cleared.
                    ArrayPool<byte>.Shared.Return(toReturn);
                }
            }

            internal void Push(StackRow row)
            {
                if (_topOfStack < StackRow.Size)
                {
                    Enlarge();
                }

                _topOfStack -= StackRow.Size;
                MemoryMarshal.Write(_rentedBuffer.AsSpan(_topOfStack), ref row);
            }

            internal StackRow Pop()
            {
                Debug.Assert(_topOfStack <= _rentedBuffer.Length - StackRow.Size);
                StackRow row = MemoryMarshal.Read<StackRow>(_rentedBuffer.AsSpan(_topOfStack));
                _topOfStack += StackRow.Size;
                return row;
            }

            private void Enlarge()
            {
                byte[] toReturn = _rentedBuffer;
                _rentedBuffer = ArrayPool<byte>.Shared.Rent(toReturn.Length * 2);

                Buffer.BlockCopy(
                    toReturn,
                    _topOfStack,
                    _rentedBuffer,
                    _rentedBuffer.Length - toReturn.Length + _topOfStack,
                    toReturn.Length - _topOfStack);

                _topOfStack += _rentedBuffer.Length - toReturn.Length;

                // The data in this rented buffer only conveys the positions and
                // lengths of tokens in a document, but no content; so it does not
                // need to be cleared.
                ArrayPool<byte>.Shared.Return(toReturn);
            }
        }
    }

    public sealed partial class JwtPayloadDocumentOld
    {
        // The database for the parsed structure of a JSON document.
        //
        // Every token from the document gets a row, which has one of the following forms:
        //
        // Number
        // * First int
        //   * Top bit is unassigned / always clear
        //   * 31 bits for token offset
        // * Second int
        //   * Top bit is set if the number uses scientific notation
        //   * 31 bits for the token length
        // * Third int
        //   * 4 bits JsonTokenType
        //   * 28 bits unassigned / always clear
        //
        // String, PropertyName
        // * First int
        //   * Top bit is unassigned / always clear
        //   * 31 bits for token offset
        // * Second int
        //   * Top bit is set if the string requires unescaping
        //   * 31 bits for the token length
        // * Third int
        //   * 4 bits JsonTokenType
        //   * 28 bits unassigned / always clear
        //
        // Other value types (True, False, Null)
        // * First int
        //   * Top bit is unassigned / always clear
        //   * 31 bits for token offset
        // * Second int
        //   * Top bit is unassigned / always clear
        //   * 31 bits for the token length
        // * Third int
        //   * 4 bits JsonTokenType
        //   * 28 bits unassigned / always clear
        //
        // EndObject / EndArray
        // * First int
        //   * Top bit is unassigned / always clear
        //   * 31 bits for token offset
        // * Second int
        //   * Top bit is unassigned / always clear
        //   * 31 bits for the token length (always 1, effectively unassigned)
        // * Third int
        //   * 4 bits JsonTokenType
        //   * 28 bits for the number of rows until the previous value (never 0)
        //
        // StartObject
        // * First int
        //   * Top bit is unassigned / always clear
        //   * 31 bits for token offset
        // * Second int
        //   * Top bit is unassigned / always clear
        //   * 31 bits for the token length (always 1, effectively unassigned)
        // * Third int
        //   * 4 bits JsonTokenType
        //   * 28 bits for the number of rows until the next value (never 0)
        //
        // StartArray
        // * First int
        //   * Top bit is unassigned / always clear
        //   * 31 bits for token offset
        // * Second int
        //   * Top bit is set if the array contains other arrays or objects ("complex" types)
        //   * 31 bits for the number of elements in this array
        // * Third int
        //   * 4 bits JsonTokenType
        //   * 28 bits for the number of rows until the next value (never 0)
        private struct MetadataDb : IDisposable
        {
            private const int SizeOrLengthOffset = 4;
            private const int NumberOfRowsOffset = 8;

            internal int Length { get; private set; }
            private byte[] _data;

            internal MetadataDb(byte[] completeDb)
            {
                _data = completeDb;
                Length = completeDb.Length;
            }

            internal MetadataDb(int payloadLength)
            {
                // Assume that a token happens approximately every 12 bytes.
                // int estimatedTokens = payloadLength / 12
                // now acknowledge that the number of bytes we need per token is 12.
                // So that's just the payload length.
                //
                // Add one token's worth of data just because.
                int initialSize = DbRow.Size + payloadLength;

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
            }

            internal MetadataDb(MetadataDb source, bool useArrayPools)
            {
                Length = source.Length;

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
            }

            internal void Append(JsonTokenType tokenType, int startLocation, int length)
            {
                // StartArray or StartObject should have length -1, otherwise the length should not be -1.
                //Debug.Assert(
                //    (tokenType == JsonTokenType.StartArray || tokenType == JsonTokenType.StartObject) ==
                //    (length == DbRow.UnknownSize));

                if (Length >= _data.Length - DbRow.Size)
                {
                    Enlarge();
                }

                DbRow row = new DbRow(tokenType, startLocation, length);
                MemoryMarshal.Write(_data.AsSpan(Length), ref row);
                Length += DbRow.Size;
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
                Debug.Assert(index <= Length - DbRow.Size, $"index {index} is out of bounds");
                Debug.Assert(index % DbRow.Size == 0, $"index {index} is not at a record start position");
            }

            internal void SetLength(int index, int length)
            {
                AssertValidIndex(index);
                Debug.Assert(length >= 0);
                Span<byte> destination = _data.AsSpan(index + SizeOrLengthOffset);
                MemoryMarshal.Write(destination, ref length);
            }

            internal void SetNumberOfRows(int index, int numberOfRows)
            {
                AssertValidIndex(index);
                Debug.Assert(numberOfRows >= 1 && numberOfRows <= 0x0FFFFFFF);

                Span<byte> dataPos = _data.AsSpan(index + NumberOfRowsOffset);
                int current = MemoryMarshal.Read<int>(dataPos);

                // Persist the most significant nybble
                int value = (current & unchecked((int)0xF0000000)) | numberOfRows;
                MemoryMarshal.Write(dataPos, ref value);
            }

            internal void SetHasComplexChildren(int index)
            {
                AssertValidIndex(index);

                // The HasComplexChildren bit is the most significant bit of "SizeOrLength"
                Span<byte> dataPos = _data.AsSpan(index + SizeOrLengthOffset);
                int current = MemoryMarshal.Read<int>(dataPos);

                int value = current | unchecked((int)0x80000000);
                MemoryMarshal.Write(dataPos, ref value);
            }

            internal int FindIndexOfFirstUnsetSizeOrLength(JsonTokenType lookupType)
            {
                Debug.Assert(lookupType == JsonTokenType.StartObject || lookupType == JsonTokenType.StartArray);
                return FindOpenElement(lookupType);
            }

            private int FindOpenElement(JsonTokenType lookupType)
            {
                Span<byte> data = _data.AsSpan(0, Length);

                for (int i = Length - DbRow.Size; i >= 0; i -= DbRow.Size)
                {
                    DbRow row = MemoryMarshal.Read<DbRow>(data.Slice(i));

                    if (row.IsUnknownSize && row.TokenType == lookupType)
                    {
                        return i;
                    }
                }

                // We should never reach here.
                Debug.Fail($"Unable to find expected {lookupType} token");
                return -1;
            }

            internal DbRow Get(int index)
            {
                AssertValidIndex(index);
                return MemoryMarshal.Read<DbRow>(_data.AsSpan(index));
            }

            internal JsonTokenType GetJsonTokenType(int index)
            {
                AssertValidIndex(index);
                uint union = MemoryMarshal.Read<uint>(_data.AsSpan(index + NumberOfRowsOffset));

                return (JsonTokenType)(union >> 28);
            }

            internal MetadataDb CopySegment(int startIndex, int endIndex)
            {
                Debug.Assert(
                    endIndex > startIndex,
                    $"endIndex={endIndex} was at or before startIndex={startIndex}");

                AssertValidIndex(startIndex);
                Debug.Assert(endIndex <= Length);

                DbRow start = Get(startIndex);
#if DEBUG
                DbRow end = Get(endIndex - DbRow.Size);

                if (start.TokenType == JsonTokenType.StartObject)
                {
                    Debug.Assert(
                        end.TokenType == JsonTokenType.EndObject,
                        $"StartObject paired with {end.TokenType}");
                }
                else if (start.TokenType == JsonTokenType.StartArray)
                {
                    Debug.Assert(
                        end.TokenType == JsonTokenType.EndArray,
                        $"StartArray paired with {end.TokenType}");
                }
                else
                {
                    Debug.Assert(
                        startIndex + DbRow.Size == endIndex,
                        $"{start.TokenType} should have been one row");
                }
#endif

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

                for (int i = (length - DbRow.Size) / sizeof(int); i >= 0; i -= DbRow.Size / sizeof(int))
                {
                    Debug.Assert(newDbInts[i] >= locationOffset);
                    newDbInts[i] -= locationOffset;
                }

                return new MetadataDb(newDatabase);
            }
        }
    }

    public sealed partial class JwtPayloadDocumentOld
    {
        [StructLayout(LayoutKind.Sequential)]
        internal readonly struct DbRow
        {
            internal const int Size = 12;

            // Sign bit is currently unassigned
            private readonly int _location;

            // Sign bit is used for "HasComplexChildren" (StartArray)
            private readonly int _sizeOrLengthUnion;

            // Top nybble is JsonTokenType
            // remaining nybbles are the number of rows to skip to get to the next value
            // This isn't limiting on the number of rows, since Span.MaxLength / sizeof(DbRow) can't
            // exceed that range.
            private readonly int _numberOfRowsAndTypeUnion;

            /// <summary>
            /// Index into the payload
            /// </summary>
            internal int Location => _location;

            /// <summary>
            /// length of text in JSON payload (or number of elements if its a JSON array)
            /// </summary>
            internal int SizeOrLength => _sizeOrLengthUnion & int.MaxValue;

            internal bool IsUnknownSize => _sizeOrLengthUnion == UnknownSize;

            /// <summary>
            /// String/PropertyName: Unescaping is required.
            /// Array: At least one element is an object/array.
            /// Otherwise; false
            /// </summary>
            internal bool HasComplexChildren => _sizeOrLengthUnion < 0;

            internal int NumberOfRows =>
                _numberOfRowsAndTypeUnion & 0x0FFFFFFF; // Number of rows that the current JSON element occupies within the database

            internal JsonTokenType TokenType => (JsonTokenType)(unchecked((uint)_numberOfRowsAndTypeUnion) >> 28);

            internal const int UnknownSize = -1;

            internal DbRow(JsonTokenType jsonTokenType, int location, int sizeOrLength)
            {
                Debug.Assert(jsonTokenType > JsonTokenType.None && jsonTokenType <= JsonTokenType.Null);
                Debug.Assert((byte)jsonTokenType < 1 << 4);
                Debug.Assert(location >= 0);
                Debug.Assert(sizeOrLength >= UnknownSize);

                _location = location;
                _sizeOrLengthUnion = sizeOrLength;
                _numberOfRowsAndTypeUnion = (int)jsonTokenType << 28;
            }

            internal bool IsSimpleValue => TokenType >= JsonTokenType.PropertyName;
        }
    }
}