using System;
using System.Buffers;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading;

namespace JsonWebToken
{
    /// <summary>
    ///   Represents the structure of a JWT value in a lightweight, read-only form.
    /// </summary>
    /// <remarks>
    ///   This class utilizes resources from pooled memory to minimize the garbage collector (GC)
    ///   impact in high-usage scenarios. Failure to properly Dispose this object will result in
    ///   the memory not being returned to the pool.
    /// </remarks>
    // Based on https://github.com/dotnet/runtime/blob/master/src/libraries/System.Text.Json/src/System/Text/Json/Document/JsonDocument.cs
    internal sealed class JwtDocument : IDisposable
    {
        internal static readonly JwtDocument Empty = new JwtDocument();

        private ReadOnlyMemory<byte> _utf8Json;
        private JsonMetadata _parsedData;
        private byte[]? _extraRentedBytes;
        private readonly JwtElement _root;
        private readonly bool _isDisposable;
        private readonly List<IDisposable> _disposableRegistry;

        /// <summary>Gets the raw binary value of the <see cref="JwtDocument"/>.</summary>
        public ReadOnlyMemory<byte> RawValue => _utf8Json;

        internal bool IsDisposable => _isDisposable;

        internal JwtDocument(ReadOnlyMemory<byte> utf8Json, JsonMetadata parsedData, byte[]? extraRentedBytes, bool isDisposable = true)
        {
            Debug.Assert(!utf8Json.IsEmpty);

            _utf8Json = utf8Json;
            _parsedData = parsedData;
            _extraRentedBytes = extraRentedBytes;
            _root = new JwtElement(this, 0);
            _isDisposable = isDisposable;
            _disposableRegistry = new List<IDisposable>();

            // extraRentedBytes better be null if we're not disposable.
            Debug.Assert(isDisposable || extraRentedBytes == null);
        }

        internal JwtDocument()
        {
            _isDisposable = false;
            _utf8Json = new byte[1];
            _disposableRegistry = new List<IDisposable>(0);
            _root = new JwtElement(this, 0);
        }

        internal bool TryGetNamedPropertyValue(ReadOnlySpan<char> propertyName, out JwtElement value)
        {
            JsonRow row;

            int maxBytes = Utf8.GetMaxByteCount(propertyName.Length);
            int endIndex = _parsedData.Length;

            if (maxBytes < JsonConstants.StackallocThreshold)
            {
                Span<byte> utf8Name = stackalloc byte[JsonConstants.StackallocThreshold];
                int len = JsonReaderHelper.GetUtf8FromText(propertyName, utf8Name);
                utf8Name = utf8Name.Slice(0, len);

                return TryGetNamedPropertyValue(
                    endIndex,
                    utf8Name,
                    out value);
            }

            // Unescaping the property name will make the string shorter (or the same)
            // So the first viable candidate is one whose length in bytes matches, or
            // exceeds, our length in chars.
            //
            // The maximal escaping seems to be 6 -> 1 ("\u0030" => "0"), but just transcode
            // and switch once one viable long property is found.
            int minBytes = propertyName.Length;
            for (int candidateIndex = 0; candidateIndex <= endIndex; candidateIndex += JsonRow.Size * 2)
            {
                row = _parsedData.Get(candidateIndex);
                Debug.Assert(row.TokenType == JsonTokenType.PropertyName);

                if (row.Length >= minBytes)
                {
                    byte[] tmpUtf8 = ArrayPool<byte>.Shared.Rent(maxBytes);
                    Span<byte> utf8Name = default;

                    try
                    {
                        int len = JsonReaderHelper.GetUtf8FromText(propertyName, tmpUtf8);
                        utf8Name = tmpUtf8.AsSpan(0, len);

                        return TryGetNamedPropertyValue(
                            candidateIndex,
                            utf8Name,
                            out value);
                    }
                    finally
                    {
                        ArrayPool<byte>.Shared.Return(tmpUtf8);
                    }
                }
            }

            // None of the property names were within the range that the UTF-8 encoding would have been.
            value = default;
            return false;
        }

        internal bool TryGetNamedPropertyValue(ReadOnlySpan<byte> propertyName, out JwtElement value)
        {
            int endIndex = _parsedData.Length;

            return TryGetNamedPropertyValue(
                endIndex,
                propertyName,
                out value);
        }

        private bool TryGetNamedPropertyValue(
            int endIndex,
            ReadOnlySpan<byte> propertyName,
            out JwtElement value)
        {
            ReadOnlySpan<byte> documentSpan = _utf8Json.Span;
            Span<byte> utf8UnescapedStack = stackalloc byte[JsonConstants.StackallocThreshold];

            // Move to the row before the EndObject
            int index = 0;

            while (index < endIndex)
            {
                JsonRow row = _parsedData.Get(index);
                Debug.Assert(row.TokenType == JsonTokenType.PropertyName);

                ReadOnlySpan<byte> currentPropertyName = documentSpan.Slice(row.Location, row.Length);

                if (row.NeedUnescaping)
                {
                    // An escaped property name will be longer than an unescaped candidate, so only unescape
                    // when the lengths are compatible.
                    if (currentPropertyName.Length > propertyName.Length)
                    {
                        int idx = currentPropertyName.IndexOf(JsonConstants.BackSlash);
                        Debug.Assert(idx >= 0);

                        // If everything up to where the property name has a backslash matches, keep going.
                        if (propertyName.Length > idx &&
                            currentPropertyName.Slice(0, idx).SequenceEqual(propertyName.Slice(0, idx)))
                        {
                            int remaining = currentPropertyName.Length - idx;
                            int written = 0;
                            byte[]? rented = null;

                            try
                            {
                                Span<byte> utf8Unescaped = remaining <= utf8UnescapedStack.Length ?
                                    utf8UnescapedStack :
                                    (rented = ArrayPool<byte>.Shared.Rent(remaining));

                                // Only unescape the part we haven't processed.
                                JsonReaderHelper.Unescape(currentPropertyName.Slice(idx), utf8Unescaped, 0, out written);

                                // If the unescaped remainder matches the input remainder, it's a match.
                                if (utf8Unescaped.Slice(0, written).SequenceEqual(propertyName.Slice(idx)))
                                {
                                    // If the property name is a match, the answer is the next element.
                                    value = new JwtElement(this, index + JsonRow.Size);
                                    return true;
                                }
                            }
                            finally
                            {
                                if (rented != null)
                                {
                                    rented.AsSpan(0, written).Clear();
                                    ArrayPool<byte>.Shared.Return(rented);
                                }
                            }
                        }
                    }
                }
                else if (currentPropertyName.SequenceEqual(propertyName))
                {
                    // If the property name is a match, the answer is the next element.
                    value = new JwtElement(this, index + JsonRow.Size);
                    return true;
                }

                // Move to the previous value
                index += JsonRow.Size * 2;
            }

            value = default;
            return false;
        }

        /// <inheritdoc />
        public void Dispose()
        {
            int length = _utf8Json.Length;
            if (length == 0 || !_isDisposable)
            {
                return;
            }

            _parsedData.Dispose();
            _utf8Json = ReadOnlyMemory<byte>.Empty;

            // When "extra rented bytes exist" they contain the document,
            // and thus need to be cleared before being returned.
            byte[]? extraRentedBytes = Interlocked.Exchange(ref _extraRentedBytes, null);

            if (extraRentedBytes != null)
            {
                extraRentedBytes.AsSpan(0, length).Clear();
                ArrayPool<byte>.Shared.Return(extraRentedBytes);
            }
        }

        internal JsonTokenType GetJsonTokenType(int index)
            => _parsedData.GetJsonTokenType(index);

        private static void CheckExpectedType(JsonTokenType expected, JsonTokenType actual)
        {
            if (expected != actual)
            {
                ThrowHelper.ThrowJsonElementWrongType_InvalidOperationException(expected, actual);
            }
        }

        internal int GetEndIndex(int index, bool includeEndElement)
        {
            JsonRow row = _parsedData.Get(index);

            if (row.IsSimpleValue)
            {
                return index + JsonRow.Size;
            }

            int endIndex = index + JsonRow.Size * row.NumberOfItems;

            if (includeEndElement)
            {
                endIndex += JsonRow.Size;
            }

            return endIndex;
        }

        private ReadOnlyMemory<byte> GetRawValue(int index, bool includeQuotes)
        {
            JsonRow row = _parsedData.Get(index);

            if (row.IsSimpleValue)
            {
                if (includeQuotes && row.TokenType == JsonTokenType.String)
                {
                    // Start one character earlier than the value (the open quote)
                    // End one character after the value (the close quote)
                    return _utf8Json.Slice(row.Location - 1, row.Length + 2);
                }

                return _utf8Json.Slice(row.Location, row.Length);
            }

            return _utf8Json.Slice(row.Location, row.Length);
        }

        private ReadOnlyMemory<byte> GetPropertyRawValue(int valueIndex)
        {
            // The property name is stored one row before the value
            JsonRow row = _parsedData.Get(valueIndex - JsonRow.Size);
            Debug.Assert(row.TokenType == JsonTokenType.PropertyName);

            // Subtract one for the open quote.
            int start = row.Location - 1;
            int end;

            row = _parsedData.Get(valueIndex);

            if (row.IsSimpleValue)
            {
                end = row.Location + row.Length;

                // If the value was a string, pick up the terminating quote.
                if (row.TokenType == JsonTokenType.String)
                {
                    end++;
                }

                return _utf8Json.Slice(start, end - start);
            }

            int endElementIdx = GetEndIndex(valueIndex, includeEndElement: false);
            row = _parsedData.Get(endElementIdx);
            end = row.Location + row.Length;
            return _utf8Json.Slice(start, end - start);
        }

        internal string? GetString(int index, JsonTokenType expectedType)
        {
            JsonRow row = _parsedData.Get(index);

            JsonTokenType tokenType = row.TokenType;

            if (tokenType == JsonTokenType.Null)
            {
                return null;
            }

            CheckExpectedType(expectedType, tokenType);

            ReadOnlySpan<byte> data = _utf8Json.Span;
            ReadOnlySpan<byte> segment = data.Slice(row.Location, row.Length);
            string value;
            int backslash = segment.IndexOf(JsonConstants.BackSlash);
            if (backslash < 0)
            {
                value = JsonReaderHelper.TranscodeHelper(segment);
            }
            else
            {
                value = JsonReaderHelper.GetUnescapedString(segment, backslash);
            }

            Debug.Assert(value != null);
            return value;
        }

        internal TValue? Deserialize<TValue>(int index, JsonSerializerOptions? options = null)
            where TValue : class
        {
            JsonRow row = _parsedData.Get(index);

            ReadOnlySpan<byte> data = _utf8Json.Span;
            ReadOnlySpan<byte> segment = data.Slice(row.Location, row.Length);
            return JsonSerializer.Deserialize<TValue>(segment, options);
        }

        internal string?[]? GetStringArray(int index)
        {
            JsonRow row = _parsedData.Get(index);

            JsonTokenType tokenType = row.TokenType;

            if (tokenType == JsonTokenType.Null)
            {
                return null;
            }

            CheckExpectedType(JsonTokenType.StartArray, tokenType);

            ReadOnlySpan<byte> data = _utf8Json.Span;
            ReadOnlySpan<byte> segment = data.Slice(row.Location, row.Length);
            string?[] array = new string[row.NumberOfItems];
            var reader = new Utf8JsonReader(segment);
            reader.Read();
            for (int i = 0; i < row.NumberOfItems; i++)
            {
                if (reader.Read())
                {
                    CheckExpectedType(JsonTokenType.String, reader.TokenType);
                    array[i] = reader.GetString();
                }
            }

            return array;
        }

        internal bool TextEquals(int index, ReadOnlySpan<char> otherText, bool isPropertyName)
        {
            int matchIndex = isPropertyName ? index - JsonRow.Size : index;

            byte[]? otherUtf8TextArray = null;

            int length = checked(otherText.Length * JsonConstants.MaxExpansionFactorWhileTranscoding);
            Span<byte> otherUtf8Text = length <= JsonConstants.StackallocThreshold ?
                stackalloc byte[JsonConstants.StackallocThreshold] :
                (otherUtf8TextArray = ArrayPool<byte>.Shared.Rent(length));

            ReadOnlySpan<byte> utf16Text = MemoryMarshal.AsBytes(otherText);
            OperationStatus status = JsonReaderHelper.ToUtf8(utf16Text, otherUtf8Text, out int consumed, out int written);
            Debug.Assert(status != OperationStatus.DestinationTooSmall);
            bool result;
            if (status > OperationStatus.DestinationTooSmall)   // Equivalent to: (status == NeedMoreData || status == InvalidData)
            {
                result = false;
            }
            else
            {
                Debug.Assert(status == OperationStatus.Done);
                Debug.Assert(consumed == utf16Text.Length);

                result = TextEquals(index, otherUtf8Text.Slice(0, written), isPropertyName, shouldUnescape: true);
            }

            if (otherUtf8TextArray != null)
            {
                otherUtf8Text.Slice(0, written).Clear();
                ArrayPool<byte>.Shared.Return(otherUtf8TextArray);
            }

            return result;
        }

        internal bool TextEquals(int index, ReadOnlySpan<byte> otherUtf8Text, bool isPropertyName, bool shouldUnescape)
        {
            int matchIndex = isPropertyName ? index - JsonRow.Size : index;

            JsonRow row = _parsedData.Get(matchIndex);

            CheckExpectedType(
                isPropertyName ? JsonTokenType.PropertyName : JsonTokenType.String,
                row.TokenType);

            ReadOnlySpan<byte> data = _utf8Json.Span;
            ReadOnlySpan<byte> segment = data.Slice(row.Location, row.Length);

            if (otherUtf8Text.Length > segment.Length || (!shouldUnescape && otherUtf8Text.Length != segment.Length))
            {
                return false;
            }

            if (row.NeedUnescaping && shouldUnescape)
            {
                if (otherUtf8Text.Length < segment.Length / JsonConstants.MaxExpansionFactorWhileEscaping)
                {
                    return false;
                }

                int idx = segment.IndexOf(JsonConstants.BackSlash);
                Debug.Assert(idx != -1);

                if (!otherUtf8Text.StartsWith(segment.Slice(0, idx)))
                {
                    return false;
                }

                return JsonReaderHelper.UnescapeAndCompare(segment.Slice(idx), otherUtf8Text.Slice(idx));
            }

            return segment.SequenceEqual(otherUtf8Text);
        }

        internal string GetNameOfPropertyValue(int index)
            => GetString(index - JsonRow.Size, JsonTokenType.PropertyName)!;

        internal bool TryGetValue(int index, out long value)
        {
            JsonRow row = _parsedData.Get(index);

            CheckExpectedType(JsonTokenType.Number, row.TokenType);

            ReadOnlySpan<byte> data = _utf8Json.Span;
            ReadOnlySpan<byte> segment = data.Slice(row.Location, row.Length);

            if (Utf8Parser.TryParse(segment, out long tmp, out int consumed) &&
                consumed == segment.Length)
            {
                value = tmp;
                return true;
            }

            value = 0;
            return false;
        }

        internal bool TryGetValue(int index, out double value)
        {
            JsonRow row = _parsedData.Get(index);

            CheckExpectedType(JsonTokenType.Number, row.TokenType);

            ReadOnlySpan<byte> data = _utf8Json.Span;
            ReadOnlySpan<byte> segment = data.Slice(row.Location, row.Length);

            if (Utf8Parser.TryParse(segment, out double tmp, out int bytesConsumed) &&
                segment.Length == bytesConsumed)
            {
                value = tmp;
                return true;
            }

            value = 0;
            return false;
        }

        internal bool TryGetValue(int index, [NotNullWhen(true)] out JsonDocument? value)
        {
            JsonRow row = _parsedData.Get(index);

            ReadOnlySpan<byte> data = _utf8Json.Span;
            ReadOnlySpan<byte> segment = data.Slice(row.Location, row.Length);
            var reader = new Utf8JsonReader(segment);

            if (JsonDocument.TryParseValue(ref reader, out var doc))
            {
                _disposableRegistry.Add(doc);
                value = doc;
                return true;
            }

            value = null;
            return false;
        }

        internal ReadOnlyMemory<byte> GetRawValue(int index)
        {
            return GetRawValue(index, includeQuotes: false);
        }

        internal string GetRawValueAsString(int index)
        {
            ReadOnlyMemory<byte> segment = GetRawValue(index, includeQuotes: true);
            return JsonReaderHelper.TranscodeHelper(segment.Span);
        }

        internal string GetPropertyRawValueAsString(int valueIndex)
        {
            ReadOnlyMemory<byte> segment = GetPropertyRawValue(valueIndex);
            return JsonReaderHelper.TranscodeHelper(segment.Span);
        }

        internal JwtElement CloneElement(int index)
        {
            int endIndex = GetEndIndex(index, true);
            JsonMetadata newDb = _parsedData.CopySegment(index, endIndex);
            ReadOnlyMemory<byte> segmentCopy = GetRawValue(index, includeQuotes: true).ToArray();

            JwtDocument newDocument = new JwtDocument(segmentCopy, newDb, extraRentedBytes: null, isDisposable: false);

            return newDocument._root;
        }

        internal JwtDocument Clone()
        {
            JsonMetadata newDb = _parsedData.Clone();
            ReadOnlyMemory<byte> segmentCopy = _utf8Json.ToArray();
            JwtDocument newDocument = new JwtDocument(segmentCopy, newDb, extraRentedBytes: null, isDisposable: false);

            return newDocument;
        }

        internal int GetArrayLength(int index)
        {
            JsonRow row = _parsedData.Get(index);

            CheckExpectedType(JsonTokenType.StartArray, row.TokenType);

            return row.Length;
        }

        internal int GetMemberCount(int index)
        {
            JsonRow row = _parsedData.Get(index);

            CheckExpectedType(JsonTokenType.StartObject, row.TokenType);

            return row.NumberOfItems;
        }

        internal JwtElement GetArrayIndexElement(int currentIndex, int arrayIndex)
        {
            JsonRow row = _parsedData.Get(currentIndex);

            CheckExpectedType(JsonTokenType.StartArray, row.TokenType);

            int arrayLength = row.Length;

            if ((uint)arrayIndex >= (uint)arrayLength)
            {
                throw new IndexOutOfRangeException();
            }

            if (!row.NeedUnescaping)
            {
                return new JwtElement(this, currentIndex + ((arrayIndex + 1) * JsonRow.Size));
            }

            int elementCount = 0;
            int objectOffset = currentIndex + JsonRow.Size;

            for (; objectOffset < _parsedData.Length; objectOffset += JsonRow.Size)
            {
                if (arrayIndex == elementCount)
                {
                    return new JwtElement(this, objectOffset);
                }

                row = _parsedData.Get(objectOffset);

                if (!row.IsSimpleValue)
                {
                    objectOffset += JsonRow.Size * row.NumberOfItems;
                }

                elementCount++;
            }

            Debug.Fail(
                $"Ran out of database searching for array index {arrayIndex} from {currentIndex} when length was {arrayLength}");
            throw new IndexOutOfRangeException();
        }


        /// <summary>Determines whether the <see cref="JwtDocument"/> contains the specified key.</summary>
        public bool ContainsKey(ReadOnlySpan<byte> key)
            => _root.TryGetProperty(key, out _);

        /// <summary>Determines whether the <see cref="JwtPayload"/> contains the specified key.</summary>
        public bool ContainsKey(string key)
            => _root.TryGetProperty(key, out _);

        /// <summary>Gets the value associated with the specified key.</summary>
        public bool TryGetProperty(ReadOnlySpan<byte> key, [NotNullWhen(true)] out JwtElement value)
            => _root.TryGetProperty(key, out value);

        /// <summary>Gets the value associated with the specified key.</summary>
        public bool TryGetProperty(string key, out JwtElement value)
        {
            if (key == null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.key);
            }

            return _root.TryGetProperty(key, out value);
        }

        /// <inheritdoc/>
        public override string ToString()
            => Utf8.GetString(_utf8Json.Span);
    }
}