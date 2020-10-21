using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text.Json;

namespace JsonWebToken
{
    //public sealed partial class JwtPayloadDocument
    //{
    //    private ReadOnlyMemory<byte> _utf8Json;
    //    private MetadataDb _parsedData;
    //    private byte[]? _extraRentedBytes;

    //    private (int, string?) _lastIndexAndString = (-1, null);
    //    private readonly bool _isDisposable;

    //    /// <summary>
    //    ///   The <see cref="JwtElement"/> representing the value of the document.
    //    /// </summary>
    //    public JwtElement RootElement => _root;
    //    private JwtPayloadDocument(ReadOnlyMemory<byte> utf8Json, MetadataDb parsedData, byte[]? extraRentedBytes,
    //        bool isDisposable = true)
    //    {
    //        Debug.Assert(!utf8Json.IsEmpty);

    //        _utf8Json = utf8Json;
    //        _parsedData = parsedData;
    //        _extraRentedBytes = extraRentedBytes;

    //        _isDisposable = isDisposable;

    //        // extraRentedBytes better be null if we're not disposable.
    //        Debug.Assert(isDisposable || extraRentedBytes == null);
    //    }
    //    internal bool TryGetNamedPropertyValue(int index, ReadOnlySpan<char> propertyName, out JwtElement value)
    //    {
    //        CheckNotDisposed();

    //        DbRow row = _parsedData.Get(index);

    //        CheckExpectedType(JsonTokenType.StartObject, row.TokenType);

    //        // Only one row means it was EndObject.
    //        if (row.NumberOfRows == 1)
    //        {
    //            value = default;
    //            return false;
    //        }

    //        int maxBytes = Utf8.GetMaxByteCount(propertyName.Length);
    //        int startIndex = index + DbRow.Size;
    //        int endIndex = checked(row.NumberOfRows * DbRow.Size + index);

    //        if (maxBytes < JsonConstants.StackallocThreshold)
    //        {
    //            Span<byte> utf8Name = stackalloc byte[JsonConstants.StackallocThreshold];
    //            int len = JsonReaderHelper.GetUtf8FromText(propertyName, utf8Name);
    //            utf8Name = utf8Name.Slice(0, len);

    //            return TryGetNamedPropertyValue(
    //                startIndex,
    //                endIndex,
    //                utf8Name,
    //                out value);
    //        }

    //        // Unescaping the property name will make the string shorter (or the same)
    //        // So the first viable candidate is one whose length in bytes matches, or
    //        // exceeds, our length in chars.
    //        //
    //        // The maximal escaping seems to be 6 -> 1 ("\u0030" => "0"), but just transcode
    //        // and switch once one viable long property is found.

    //        int minBytes = propertyName.Length;
    //        // Move to the row before the EndObject
    //        int candidateIndex = endIndex - DbRow.Size;

    //        while (candidateIndex > index)
    //        {
    //            int passedIndex = candidateIndex;

    //            row = _parsedData.Get(candidateIndex);
    //            Debug.Assert(row.TokenType != JsonTokenType.PropertyName);

    //            // Move before the value
    //            if (row.IsSimpleValue)
    //            {
    //                candidateIndex -= DbRow.Size;
    //            }
    //            else
    //            {
    //                Debug.Assert(row.NumberOfRows > 0);
    //                candidateIndex -= DbRow.Size * (row.NumberOfRows + 1);
    //            }

    //            row = _parsedData.Get(candidateIndex);
    //            Debug.Assert(row.TokenType == JsonTokenType.PropertyName);

    //            if (row.SizeOrLength >= minBytes)
    //            {
    //                byte[] tmpUtf8 = ArrayPool<byte>.Shared.Rent(maxBytes);
    //                Span<byte> utf8Name = default;

    //                try
    //                {
    //                    int len = JsonReaderHelper.GetUtf8FromText(propertyName, tmpUtf8);
    //                    utf8Name = tmpUtf8.AsSpan(0, len);

    //                    return TryGetNamedPropertyValue(
    //                        startIndex,
    //                        passedIndex + DbRow.Size,
    //                        utf8Name,
    //                        out value);
    //                }
    //                finally
    //                {
    //                    ArrayPool<byte>.Shared.Return(tmpUtf8);
    //                }
    //            }

    //            // Move to the previous value
    //            candidateIndex -= DbRow.Size;
    //        }

    //        // None of the property names were within the range that the UTF-8 encoding would have been.
    //        value = default;
    //        return false;
    //    }

    //    internal bool TryGetNamedPropertyValue(int index, ReadOnlySpan<byte> propertyName, out JwtElement value)
    //    {
    //        CheckNotDisposed();

    //        DbRow row = _parsedData.Get(index);

    //        CheckExpectedType(JsonTokenType.StartObject, row.TokenType);

    //        // Only one row means it was EndObject.
    //        if (row.NumberOfRows == 1)
    //        {
    //            value = default;
    //            return false;
    //        }

    //        int endIndex = checked(row.NumberOfRows * DbRow.Size + index);

    //        return TryGetNamedPropertyValue(
    //            index + DbRow.Size,
    //            endIndex,
    //            propertyName,
    //            out value);
    //    }

    //    private bool TryGetNamedPropertyValue(
    //        int startIndex,
    //        int endIndex,
    //        ReadOnlySpan<byte> propertyName,
    //        out JwtElement value)
    //    {
    //        ReadOnlySpan<byte> documentSpan = _utf8Json.Span;
    //        Span<byte> utf8UnescapedStack = stackalloc byte[JsonConstants.StackallocThreshold];

    //        // Move to the row before the EndObject
    //        int index = endIndex - DbRow.Size;

    //        while (index > startIndex)
    //        {
    //            DbRow row = _parsedData.Get(index);
    //            Debug.Assert(row.TokenType != JsonTokenType.PropertyName);

    //            // Move before the value
    //            if (row.IsSimpleValue)
    //            {
    //                index -= DbRow.Size;
    //            }
    //            else
    //            {
    //                //       Debug.Assert(row.NumberOfRows > 0);
    //                index -= DbRow.Size * (row.NumberOfRows + 1);
    //            }

    //            row = _parsedData.Get(index);
    //            Debug.Assert(row.TokenType == JsonTokenType.PropertyName);

    //            ReadOnlySpan<byte> currentPropertyName = documentSpan.Slice(row.Location, row.SizeOrLength);

    //            if (row.HasComplexChildren)
    //            {
    //                // An escaped property name will be longer than an unescaped candidate, so only unescape
    //                // when the lengths are compatible.
    //                if (currentPropertyName.Length > propertyName.Length)
    //                {
    //                    int idx = currentPropertyName.IndexOf(JsonConstants.BackSlash);
    //                    Debug.Assert(idx >= 0);

    //                    // If everything up to where the property name has a backslash matches, keep going.
    //                    if (propertyName.Length > idx &&
    //                        currentPropertyName.Slice(0, idx).SequenceEqual(propertyName.Slice(0, idx)))
    //                    {
    //                        int remaining = currentPropertyName.Length - idx;
    //                        int written = 0;
    //                        byte[]? rented = null;

    //                        try
    //                        {
    //                            Span<byte> utf8Unescaped = remaining <= utf8UnescapedStack.Length ?
    //                                utf8UnescapedStack :
    //                                (rented = ArrayPool<byte>.Shared.Rent(remaining));

    //                            // Only unescape the part we haven't processed.
    //                            JsonReaderHelper.Unescape(currentPropertyName.Slice(idx), utf8Unescaped, 0, out written);

    //                            // If the unescaped remainder matches the input remainder, it's a match.
    //                            if (utf8Unescaped.Slice(0, written).SequenceEqual(propertyName.Slice(idx)))
    //                            {
    //                                // If the property name is a match, the answer is the next element.
    //                                value = new JwtElement(this, index + DbRow.Size);
    //                                return true;
    //                            }
    //                        }
    //                        finally
    //                        {
    //                            if (rented != null)
    //                            {
    //                                rented.AsSpan(0, written).Clear();
    //                                ArrayPool<byte>.Shared.Return(rented);
    //                            }
    //                        }
    //                    }
    //                }
    //            }
    //            else if (currentPropertyName.SequenceEqual(propertyName))
    //            {
    //                // If the property name is a match, the answer is the next element.
    //                value = new JwtElement(this, index + DbRow.Size);
    //                return true;
    //            }

    //            // Move to the previous value
    //            index -= DbRow.Size;
    //        }

    //        value = default;
    //        return false;
    //    }

    //    /// <inheritdoc />
    //    public void Dispose()
    //    {
    //        int length = _utf8Json.Length;
    //        if (length == 0 || !_isDisposable)
    //        {
    //            return;
    //        }

    //        _parsedData.Dispose();
    //        _utf8Json = ReadOnlyMemory<byte>.Empty;

    //        // When "extra rented bytes exist" they contain the document,
    //        // and thus need to be cleared before being returned.
    //        byte[]? extraRentedBytes = Interlocked.Exchange(ref _extraRentedBytes, null);

    //        if (extraRentedBytes != null)
    //        {
    //            extraRentedBytes.AsSpan(0, length).Clear();
    //            ArrayPool<byte>.Shared.Return(extraRentedBytes);
    //        }
    //    }

    //    internal JsonTokenType GetJsonTokenType(int index)
    //    {
    //        CheckNotDisposed();

    //        return _parsedData.GetJsonTokenType(index);
    //    }

    //    private void CheckExpectedType(JsonTokenType expected, JsonTokenType actual)
    //    {
    //        if (expected != actual)
    //        {
    //            //throw ThrowHelper.GetJsonElementWrongTypeException(expected, actual);
    //            throw new InvalidOperationException();
    //        }
    //    }

    //    private void CheckNotDisposed()
    //    {
    //        if (_utf8Json.IsEmpty)
    //        {
    //            ThrowHelper.ThrowObjectDisposedException(typeof(JwtPayloadDocument));
    //        }
    //    }

    //    internal int GetEndIndex(int index, bool includeEndElement)
    //    {
    //        CheckNotDisposed();

    //        DbRow row = _parsedData.Get(index);

    //        if (row.IsSimpleValue)
    //        {
    //            return index + DbRow.Size;
    //        }

    //        int endIndex = index + DbRow.Size * row.NumberOfRows;

    //        if (includeEndElement)
    //        {
    //            endIndex += DbRow.Size;
    //        }

    //        return endIndex;
    //    }

    //    private ReadOnlyMemory<byte> GetRawValue(int index, bool includeQuotes)
    //    {
    //        CheckNotDisposed();

    //        DbRow row = _parsedData.Get(index);

    //        if (row.IsSimpleValue)
    //        {
    //            if (includeQuotes && row.TokenType == JsonTokenType.String)
    //            {
    //                // Start one character earlier than the value (the open quote)
    //                // End one character after the value (the close quote)
    //                return _utf8Json.Slice(row.Location - 1, row.SizeOrLength + 2);
    //            }

    //            return _utf8Json.Slice(row.Location, row.SizeOrLength);
    //        }

    //        int endElementIdx = GetEndIndex(index, includeEndElement: false);
    //        int start = row.Location;
    //        row = _parsedData.Get(endElementIdx);
    //        return _utf8Json.Slice(start, row.Location - start + row.SizeOrLength);
    //    }

    //    private ReadOnlyMemory<byte> GetPropertyRawValue(int valueIndex)
    //    {
    //        CheckNotDisposed();

    //        // The property name is stored one row before the value
    //        DbRow row = _parsedData.Get(valueIndex - DbRow.Size);
    //        Debug.Assert(row.TokenType == JsonTokenType.PropertyName);

    //        // Subtract one for the open quote.
    //        int start = row.Location - 1;
    //        int end;

    //        row = _parsedData.Get(valueIndex);

    //        if (row.IsSimpleValue)
    //        {
    //            end = row.Location + row.SizeOrLength;

    //            // If the value was a string, pick up the terminating quote.
    //            if (row.TokenType == JsonTokenType.String)
    //            {
    //                end++;
    //            }

    //            return _utf8Json.Slice(start, end - start);
    //        }

    //        int endElementIdx = GetEndIndex(valueIndex, includeEndElement: false);
    //        row = _parsedData.Get(endElementIdx);
    //        end = row.Location + row.SizeOrLength;
    //        return _utf8Json.Slice(start, end - start);
    //    }

    //    internal string? GetString(int index, JsonTokenType expectedType)
    //    {
    //        CheckNotDisposed();

    //        (int lastIdx, string? lastString) = _lastIndexAndString;

    //        if (lastIdx == index)
    //        {
    //            Debug.Assert(lastString != null);
    //            return lastString;
    //        }

    //        DbRow row = _parsedData.Get(index);

    //        JsonTokenType tokenType = row.TokenType;

    //        if (tokenType == JsonTokenType.Null)
    //        {
    //            return null;
    //        }

    //        CheckExpectedType(expectedType, tokenType);

    //        ReadOnlySpan<byte> data = _utf8Json.Span;
    //        ReadOnlySpan<byte> segment = data.Slice(row.Location, row.SizeOrLength);

    //        if (row.HasComplexChildren)
    //        {
    //            int backslash = segment.IndexOf(JsonConstants.BackSlash);
    //            lastString = JsonReaderHelper.GetUnescapedString(segment, backslash);
    //        }
    //        else
    //        {
    //            lastString = JsonReaderHelper.TranscodeHelper(segment);
    //        }

    //        Debug.Assert(lastString != null);
    //        _lastIndexAndString = (index, lastString);
    //        return lastString;
    //    }

    //    internal bool TextEquals(int index, ReadOnlySpan<char> otherText, bool isPropertyName)
    //    {
    //        CheckNotDisposed();

    //        int matchIndex = isPropertyName ? index - DbRow.Size : index;

    //        (int lastIdx, string? lastString) = _lastIndexAndString;

    //        if (lastIdx == matchIndex)
    //        {
    //            return otherText.SequenceEqual(lastString.AsSpan());
    //        }

    //        byte[]? otherUtf8TextArray = null;

    //        int length = checked(otherText.Length * JsonConstants.MaxExpansionFactorWhileTranscoding);
    //        Span<byte> otherUtf8Text = length <= JsonConstants.StackallocThreshold ?
    //            stackalloc byte[JsonConstants.StackallocThreshold] :
    //            (otherUtf8TextArray = ArrayPool<byte>.Shared.Rent(length));

    //        ReadOnlySpan<byte> utf16Text = MemoryMarshal.AsBytes(otherText);
    //        OperationStatus status = JsonReaderHelper.ToUtf8(utf16Text, otherUtf8Text, out int consumed, out int written);
    //        Debug.Assert(status != OperationStatus.DestinationTooSmall);
    //        bool result;
    //        if (status > OperationStatus.DestinationTooSmall)   // Equivalent to: (status == NeedMoreData || status == InvalidData)
    //        {
    //            result = false;
    //        }
    //        else
    //        {
    //            Debug.Assert(status == OperationStatus.Done);
    //            Debug.Assert(consumed == utf16Text.Length);

    //            result = TextEquals(index, otherUtf8Text.Slice(0, written), isPropertyName, shouldUnescape: true);
    //        }

    //        if (otherUtf8TextArray != null)
    //        {
    //            otherUtf8Text.Slice(0, written).Clear();
    //            ArrayPool<byte>.Shared.Return(otherUtf8TextArray);
    //        }

    //        return result;
    //    }

    //    internal bool TextEquals(int index, ReadOnlySpan<byte> otherUtf8Text, bool isPropertyName, bool shouldUnescape)
    //    {
    //        CheckNotDisposed();

    //        int matchIndex = isPropertyName ? index - DbRow.Size : index;

    //        DbRow row = _parsedData.Get(matchIndex);

    //        CheckExpectedType(
    //            isPropertyName ? JsonTokenType.PropertyName : JsonTokenType.String,
    //            row.TokenType);

    //        ReadOnlySpan<byte> data = _utf8Json.Span;
    //        ReadOnlySpan<byte> segment = data.Slice(row.Location, row.SizeOrLength);

    //        if (otherUtf8Text.Length > segment.Length || (!shouldUnescape && otherUtf8Text.Length != segment.Length))
    //        {
    //            return false;
    //        }

    //        if (row.HasComplexChildren && shouldUnescape)
    //        {
    //            if (otherUtf8Text.Length < segment.Length / JsonConstants.MaxExpansionFactorWhileEscaping)
    //            {
    //                return false;
    //            }

    //            int idx = segment.IndexOf(JsonConstants.BackSlash);
    //            Debug.Assert(idx != -1);

    //            if (!otherUtf8Text.StartsWith(segment.Slice(0, idx)))
    //            {
    //                return false;
    //            }

    //            return JsonReaderHelper.UnescapeAndCompare(segment.Slice(idx), otherUtf8Text.Slice(idx));
    //        }

    //        return segment.SequenceEqual(otherUtf8Text);
    //    }

    //    internal string GetNameOfPropertyValue(int index)
    //    {
    //        // The property name is one row before the property value
    //        return GetString(index - DbRow.Size, JsonTokenType.PropertyName)!;
    //    }

    //    internal bool TryGetValue(int index, out long value)
    //    {
    //        CheckNotDisposed();

    //        DbRow row = _parsedData.Get(index);

    //        CheckExpectedType(JsonTokenType.Number, row.TokenType);

    //        ReadOnlySpan<byte> data = _utf8Json.Span;
    //        ReadOnlySpan<byte> segment = data.Slice(row.Location, row.SizeOrLength);

    //        if (Utf8Parser.TryParse(segment, out long tmp, out int consumed) &&
    //            consumed == segment.Length)
    //        {
    //            value = tmp;
    //            return true;
    //        }

    //        value = 0;
    //        return false;
    //    }

    //    internal bool TryGetValue(int index, out double value)
    //    {
    //        CheckNotDisposed();

    //        DbRow row = _parsedData.Get(index);

    //        CheckExpectedType(JsonTokenType.Number, row.TokenType);

    //        ReadOnlySpan<byte> data = _utf8Json.Span;
    //        ReadOnlySpan<byte> segment = data.Slice(row.Location, row.SizeOrLength);

    //        if (Utf8Parser.TryParse(segment, out double tmp, out int bytesConsumed) &&
    //            segment.Length == bytesConsumed)
    //        {
    //            value = tmp;
    //            return true;
    //        }

    //        value = 0;
    //        return false;
    //    }
    //    internal bool TryGetValue(int index, out JsonDocument? value)
    //    {
    //        CheckNotDisposed();

    //        DbRow row = _parsedData.Get(index);

    //        CheckExpectedType(JsonTokenType.StartObject, row.TokenType);

    //        ReadOnlySpan<byte> data = _utf8Json.Span;
    //        ReadOnlySpan<byte> segment = data.Slice(row.Location, row.SizeOrLength);
    //        var reader = new Utf8JsonReader(segment);

    //        if (JsonDocument.TryParseValue(ref reader, out var tmp))
    //        {
    //            value = tmp;
    //            return true;
    //        }

    //        value = null;
    //        return false;
    //    }

    //    internal string GetRawValueAsString(int index)
    //    {
    //        ReadOnlyMemory<byte> segment = GetRawValue(index, includeQuotes: true);
    //        return JsonReaderHelper.TranscodeHelper(segment.Span);
    //    }

    //    internal string GetPropertyRawValueAsString(int valueIndex)
    //    {
    //        ReadOnlyMemory<byte> segment = GetPropertyRawValue(valueIndex);
    //        return JsonReaderHelper.TranscodeHelper(segment.Span);
    //    }

    //    internal JwtElement CloneElement(int index)
    //    {
    //        int endIndex = GetEndIndex(index, true);
    //        MetadataDb newDb = _parsedData.CopySegment(index, endIndex);
    //        ReadOnlyMemory<byte> segmentCopy = GetRawValue(index, includeQuotes: true).ToArray();

    //        JwtPayloadDocument newDocument = new JwtPayloadDocument(segmentCopy, newDb, extraRentedBytes: null, isDisposable: false);

    //        return newDocument._root;
    //    }

    //    internal int GetArrayLength(int index)
    //    {
    //        CheckNotDisposed();

    //        DbRow row = _parsedData.Get(index);

    //        CheckExpectedType(JsonTokenType.StartArray, row.TokenType);

    //        return row.SizeOrLength;
    //    }

    //    internal JwtElement GetArrayIndexElement(int currentIndex, int arrayIndex)
    //    {
    //        CheckNotDisposed();

    //        DbRow row = _parsedData.Get(currentIndex);

    //        CheckExpectedType(JsonTokenType.StartArray, row.TokenType);

    //        int arrayLength = row.SizeOrLength;

    //        if ((uint)arrayIndex >= (uint)arrayLength)
    //        {
    //            throw new IndexOutOfRangeException();
    //        }

    //        if (!row.HasComplexChildren)
    //        {
    //            // Since we wouldn't be here without having completed the document parse, and we
    //            // already vetted the index against the length, this new index will always be
    //            // within the table.
    //            return new JwtElement(this, currentIndex + ((arrayIndex + 1) * DbRow.Size));
    //        }

    //        int elementCount = 0;
    //        int objectOffset = currentIndex + DbRow.Size;

    //        for (; objectOffset < _parsedData.Length; objectOffset += DbRow.Size)
    //        {
    //            if (arrayIndex == elementCount)
    //            {
    //                return new JwtElement(this, objectOffset);
    //            }

    //            row = _parsedData.Get(objectOffset);

    //            if (!row.IsSimpleValue)
    //            {
    //                objectOffset += DbRow.Size * row.NumberOfRows;
    //            }

    //            elementCount++;
    //        }

    //        Debug.Fail(
    //            $"Ran out of database searching for array index {arrayIndex} from {currentIndex} when length was {arrayLength}");
    //        throw new IndexOutOfRangeException();
    //    }
    //}

    /// <summary>
    ///   Represents a specific JWT value within a <see cref="JwtDocument"/>.
    /// </summary>
    [DebuggerDisplay("{DebuggerDisplay,nq}")]
    public readonly partial struct JwtElement
    {
        private readonly JwtDocument _parent;
        private readonly int _idx;

        internal JwtElement(JwtDocument parent, int idx)
        {
            // parent is usually not null, but the Current property
            // on the enumerators (when initialized as `default`) can
            // get here with a null.
            Debug.Assert(idx >= 0);

            _parent = parent;
            _idx = idx;
        }

        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private JsonTokenType TokenType
        {
            get
            {
                return _parent?.GetJsonTokenType(_idx) ?? JsonTokenType.None;
            }
        }
        /// <summary>
        ///   The <see cref="JsonValueKind"/> that the value is.
        /// </summary>
        /// <exception cref="ObjectDisposedException">
        ///   The parent <see cref="JsonDocument"/> has been disposed.
        /// </exception>
        public JsonValueKind ValueKind => ToValueKind(TokenType);

        /// <summary>
        ///   Get the value at a specified index when the current value is a
        ///   <see cref="JsonValueKind.Array"/>.
        /// </summary>
        /// <exception cref="InvalidOperationException">
        ///   This value's <see cref="ValueKind"/> is not <see cref="JsonValueKind.Array"/>.
        /// </exception>
        /// <exception cref="IndexOutOfRangeException">
        ///   <paramref name="index"/> is not in the range [0, <see cref="GetArrayLength"/>()).
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        ///   The parent <see cref="JsonDocument"/> has been disposed.
        /// </exception>
        public JwtElement this[int index]
        {
            get
            {
                CheckValidInstance();

                return _parent.GetArrayIndexElement(_idx, index);
            }
        }

        /// <summary>
        ///   Get the number of values contained within the current array value.
        /// </summary>
        /// <returns>The number of values contained within the current array value.</returns>
        /// <exception cref="InvalidOperationException">
        ///   This value's <see cref="ValueKind"/> is not <see cref="JsonValueKind.Array"/>.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        ///   The parent <see cref="JsonDocument"/> has been disposed.
        /// </exception>
        public int GetArrayLength()
        {
            CheckValidInstance();

            return _parent.GetArrayLength(_idx);
        }

        /// <summary>
        ///   Gets a <see cref="JwtElement"/> representing the value of a required property identified
        ///   by <paramref name="propertyName"/>.
        /// </summary>
        /// <remarks>
        ///   Property name matching is performed as an ordinal, case-sensitive, comparison.
        ///
        ///   If a property is defined multiple times for the same object, the last such definition is
        ///   what is matched.
        /// </remarks>
        /// <param name="propertyName">Name of the property whose value to return.</param>
        /// <returns>
        ///   A <see cref="JwtElement"/> representing the value of the requested property.
        /// </returns>
        /// <seealso cref="EnumerateObject"/>
        /// <exception cref="InvalidOperationException">
        ///   This value's <see cref="ValueKind"/> is not <see cref="JsonValueKind.Object"/>.
        /// </exception>
        /// <exception cref="KeyNotFoundException">
        ///   No property was found with the requested name.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="propertyName"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        ///   The parent <see cref="JsonDocument"/> has been disposed.
        /// </exception>
        public JwtElement GetProperty(string propertyName)
        {
            if (propertyName == null)
                throw new ArgumentNullException(nameof(propertyName));

            if (TryGetProperty(propertyName, out JwtElement property))
            {
                return property;
            }

            throw new KeyNotFoundException();
        }

        /// <summary>
        ///   Gets a <see cref="JwtElement"/> representing the value of a required property identified
        ///   by <paramref name="propertyName"/>.
        /// </summary>
        /// <remarks>
        ///   <para>
        ///     Property name matching is performed as an ordinal, case-sensitive, comparison.
        ///   </para>
        ///
        ///   <para>
        ///     If a property is defined multiple times for the same object, the last such definition is
        ///     what is matched.
        ///   </para>
        /// </remarks>
        /// <param name="propertyName">Name of the property whose value to return.</param>
        /// <returns>
        ///   A <see cref="JwtElement"/> representing the value of the requested property.
        /// </returns>
        /// <seealso cref="EnumerateObject"/>
        /// <exception cref="InvalidOperationException">
        ///   This value's <see cref="ValueKind"/> is not <see cref="JsonValueKind.Object"/>.
        /// </exception>
        /// <exception cref="KeyNotFoundException">
        ///   No property was found with the requested name.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        ///   The parent <see cref="JsonDocument"/> has been disposed.
        /// </exception>
        public JwtElement GetProperty(ReadOnlySpan<char> propertyName)
        {
            if (TryGetProperty(propertyName, out JwtElement property))
            {
                return property;
            }

            throw new KeyNotFoundException();
        }

        /// <summary>
        ///   Gets a <see cref="JwtElement"/> representing the value of a required property identified
        ///   by <paramref name="utf8PropertyName"/>.
        /// </summary>
        /// <remarks>
        ///   <para>
        ///     Property name matching is performed as an ordinal, case-sensitive, comparison.
        ///   </para>
        ///
        ///   <para>
        ///     If a property is defined multiple times for the same object, the last such definition is
        ///     what is matched.
        ///   </para>
        /// </remarks>
        /// <param name="utf8PropertyName">
        ///   The UTF-8 (with no Byte-Order-Mark (BOM)) representation of the name of the property to return.
        /// </param>
        /// <returns>
        ///   A <see cref="JwtElement"/> representing the value of the requested property.
        /// </returns>
        /// <exception cref="InvalidOperationException">
        ///   This value's <see cref="ValueKind"/> is not <see cref="JsonValueKind.Object"/>.
        /// </exception>
        /// <exception cref="KeyNotFoundException">
        ///   No property was found with the requested name.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        ///   The parent <see cref="JsonDocument"/> has been disposed.
        /// </exception>
        /// <seealso cref="EnumerateObject"/>
        public JwtElement GetProperty(ReadOnlySpan<byte> utf8PropertyName)
        {
            if (TryGetProperty(utf8PropertyName, out JwtElement property))
            {
                return property;
            }

            throw new KeyNotFoundException();
        }

        /// <summary>
        ///   Looks for a property named <paramref name="propertyName"/> in the current object, returning
        ///   whether or not such a property existed. When the property exists <paramref name="value"/>
        ///   is assigned to the value of that property.
        /// </summary>
        /// <remarks>
        ///   <para>
        ///     Property name matching is performed as an ordinal, case-sensitive, comparison.
        ///   </para>
        ///
        ///   <para>
        ///     If a property is defined multiple times for the same object, the last such definition is
        ///     what is matched.
        ///   </para>
        /// </remarks>
        /// <param name="propertyName">Name of the property to find.</param>
        /// <param name="value">Receives the value of the located property.</param>
        /// <returns>
        ///   <see langword="true"/> if the property was found, <see langword="false"/> otherwise.
        /// </returns>
        /// <exception cref="InvalidOperationException">
        ///   This value's <see cref="ValueKind"/> is not <see cref="JsonValueKind.Object"/>.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="propertyName"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        ///   The parent <see cref="JsonDocument"/> has been disposed.
        /// </exception>
        /// <seealso cref="EnumerateObject"/>
        public bool TryGetProperty(string propertyName, out JwtElement value)
        {
            if (propertyName == null)
                throw new ArgumentNullException(nameof(propertyName));

            return TryGetProperty(propertyName.AsSpan(), out value);
        }

        /// <summary>
        ///   Looks for a property named <paramref name="propertyName"/> in the current object, returning
        ///   whether or not such a property existed. When the property exists <paramref name="value"/>
        ///   is assigned to the value of that property.
        /// </summary>
        /// <remarks>
        ///   <para>
        ///     Property name matching is performed as an ordinal, case-sensitive, comparison.
        ///   </para>
        ///
        ///   <para>
        ///     If a property is defined multiple times for the same object, the last such definition is
        ///     what is matched.
        ///   </para>
        /// </remarks>
        /// <param name="propertyName">Name of the property to find.</param>
        /// <param name="value">Receives the value of the located property.</param>
        /// <returns>
        ///   <see langword="true"/> if the property was found, <see langword="false"/> otherwise.
        /// </returns>
        /// <seealso cref="EnumerateObject"/>
        /// <exception cref="InvalidOperationException">
        ///   This value's <see cref="ValueKind"/> is not <see cref="JsonValueKind.Object"/>.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        ///   The parent <see cref="JsonDocument"/> has been disposed.
        /// </exception>
        public bool TryGetProperty(ReadOnlySpan<char> propertyName, out JwtElement value)
        {
            CheckValidInstance();

            return _parent.TryGetNamedPropertyValue(_idx, propertyName, out value);
        }

        /// <summary>
        ///   Looks for a property named <paramref name="utf8PropertyName"/> in the current object, returning
        ///   whether or not such a property existed. When the property exists <paramref name="value"/>
        ///   is assigned to the value of that property.
        /// </summary>
        /// <remarks>
        ///   <para>
        ///     Property name matching is performed as an ordinal, case-sensitive, comparison.
        ///   </para>
        ///
        ///   <para>
        ///     If a property is defined multiple times for the same object, the last such definition is
        ///     what is matched.
        ///   </para>
        /// </remarks>
        /// <param name="utf8PropertyName">
        ///   The UTF-8 (with no Byte-Order-Mark (BOM)) representation of the name of the property to return.
        /// </param>
        /// <param name="value">Receives the value of the located property.</param>
        /// <returns>
        ///   <see langword="true"/> if the property was found, <see langword="false"/> otherwise.
        /// </returns>
        /// <seealso cref="EnumerateObject"/>
        /// <exception cref="InvalidOperationException">
        ///   This value's <see cref="ValueKind"/> is not <see cref="JsonValueKind.Object"/>.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        ///   The parent <see cref="JsonDocument"/> has been disposed.
        /// </exception>
        public bool TryGetProperty(ReadOnlySpan<byte> utf8PropertyName, out JwtElement value)
        {
            CheckValidInstance();

            return _parent.TryGetNamedPropertyValue(_idx, utf8PropertyName, out value);
        }

        /// <summary>
        ///   Gets the value of the element as a <see cref="bool"/>.
        /// </summary>
        /// <remarks>
        ///   This method does not parse the contents of a JSON string value.
        /// </remarks>
        /// <returns>The value of the element as a <see cref="bool"/>.</returns>
        /// <exception cref="InvalidOperationException">
        ///   This value's <see cref="ValueKind"/> is neither <see cref="JsonValueKind.True"/> or
        ///   <see cref="JsonValueKind.False"/>.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        ///   The parent <see cref="JsonDocument"/> has been disposed.
        /// </exception>
        public bool GetBoolean()
        {
            // CheckValidInstance is redundant.  Asking for the type will
            // return None, which then throws the same exception in the return statement.

            JsonTokenType type = TokenType;

            return
                type == JsonTokenType.True ? true :
                type == JsonTokenType.False ? false :
                throw ThrowHelper.CreateInvalidOperationException_NotSupportedJsonType(/*nameof(Boolean), type*/JwtTokenType.Boolean);
        }

        /// <summary>
        ///   Gets the value of the element as a <see cref="string"/>.
        /// </summary>
        /// <remarks>
        ///   This method does not create a string representation of values other than JSON strings.
        /// </remarks>
        /// <returns>The value of the element as a <see cref="string"/>.</returns>
        /// <exception cref="InvalidOperationException">
        ///   This value's <see cref="ValueKind"/> is neither <see cref="JsonValueKind.String"/> nor <see cref="JsonValueKind.Null"/>.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        ///   The parent <see cref="JsonDocument"/> has been disposed.
        /// </exception>
        /// <seealso cref="ToString"/>
        public string? GetString()
        {
            CheckValidInstance();

            return _parent.GetString(_idx, JsonTokenType.String);
        }

        /// <summary>
        ///   Attempts to represent the current JSON number as a <see cref="long"/>.
        /// </summary>
        /// <param name="value">Receives the value.</param>
        /// <remarks>
        ///   This method does not parse the contents of a JSON string value.
        /// </remarks>
        /// <returns>
        ///   <see langword="true"/> if the number can be represented as a <see cref="long"/>,
        ///   <see langword="false"/> otherwise.
        /// </returns>
        /// <exception cref="InvalidOperationException">
        ///   This value's <see cref="ValueKind"/> is not <see cref="JsonValueKind.Number"/>.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        ///   The parent <see cref="JsonDocument"/> has been disposed.
        /// </exception>
        public bool TryGetInt64(out long value)
        {
            CheckValidInstance();

            return _parent.TryGetValue(_idx, out value);
        }

        /// <summary>
        ///   Gets the current JSON number as a <see cref="long"/>.
        /// </summary>
        /// <returns>The current JSON number as a <see cref="long"/>.</returns>
        /// <remarks>
        ///   This method does not parse the contents of a JSON string value.
        /// </remarks>
        /// <exception cref="InvalidOperationException">
        ///   This value's <see cref="ValueKind"/> is not <see cref="JsonValueKind.Number"/>.
        /// </exception>
        /// <exception cref="FormatException">
        ///   The value cannot be represented as a <see cref="long"/>.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        ///   The parent <see cref="JsonDocument"/> has been disposed.
        /// </exception>
        public long GetInt64()
        {
            if (TryGetInt64(out long value))
            {
                return value;
            }

            throw ThrowHelper.CreateFormatException_MalformedJson();
        }

        /// <summary>
        ///   Attempts to represent the current JSON number as a <see cref="double"/>.
        /// </summary>
        /// <param name="value">Receives the value.</param>
        /// <remarks>
        ///   <para>
        ///     This method does not parse the contents of a JSON string value.
        ///   </para>
        ///
        ///   <para>
        ///     On .NET Core this method does not return <see langword="false"/> for values larger than
        ///     <see cref="double.MaxValue"/> (or smaller than <see cref="double.MinValue"/>),
        ///     instead <see langword="true"/> is returned and <see cref="double.PositiveInfinity"/> (or
        ///     <see cref="double.NegativeInfinity"/>) is emitted.
        ///   </para>
        /// </remarks>
        /// <returns>
        ///   <see langword="true"/> if the number can be represented as a <see cref="double"/>,
        ///   <see langword="false"/> otherwise.
        /// </returns>
        /// <exception cref="InvalidOperationException">
        ///   This value's <see cref="ValueKind"/> is not <see cref="JsonValueKind.Number"/>.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        ///   The parent <see cref="JsonDocument"/> has been disposed.
        /// </exception>
        public bool TryGetDouble(out double value)
        {
            CheckValidInstance();

            return _parent.TryGetValue(_idx, out value);
        }

        public bool TryGetJsonDocument(out JsonDocument? value)
        {
            CheckValidInstance();

            bool result = _parent.TryGetValue(_idx, out value);
            if (result)
            {
                _parent.RegisterToDispose(value);
            }

            return result;
        }

        /// <summary>
        ///   Gets the current JSON number as a <see cref="double"/>.
        /// </summary>
        /// <returns>The current JSON number as a <see cref="double"/>.</returns>
        /// <remarks>
        ///   <para>
        ///     This method does not parse the contents of a JSON string value.
        ///   </para>
        ///
        ///   <para>
        ///     On .NET Core this method returns <see cref="double.PositiveInfinity"/> (or
        ///     <see cref="double.NegativeInfinity"/>) for values larger than
        ///     <see cref="double.MaxValue"/> (or smaller than <see cref="double.MinValue"/>).
        ///   </para>
        /// </remarks>
        /// <exception cref="InvalidOperationException">
        ///   This value's <see cref="ValueKind"/> is not <see cref="JsonValueKind.Number"/>.
        /// </exception>
        /// <exception cref="FormatException">
        ///   The value cannot be represented as a <see cref="double"/>.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        ///   The parent <see cref="JsonDocument"/> has been disposed.
        /// </exception>
        public double GetDouble()
        {
            if (TryGetDouble(out double value))
            {
                return value;
            }

            throw ThrowHelper.CreateFormatException_MalformedJson();
        }

        public JsonDocument GetJsonDocument()
        {
            if (TryGetJsonDocument(out JsonDocument value))
            {
                return value;
            }

            throw ThrowHelper.CreateFormatException_MalformedJson();
        }

        internal string GetPropertyName()
        {
            CheckValidInstance();

            return _parent.GetNameOfPropertyValue(_idx);
        }

        /// <summary>
        ///   Gets the original input data backing this value, returning it as a <see cref="string"/>.
        /// </summary>
        /// <returns>
        ///   The original input data backing this value, returning it as a <see cref="string"/>.
        /// </returns>
        /// <exception cref="ObjectDisposedException">
        ///   The parent <see cref="Jwt"/> has been disposed.
        /// </exception>
        public string GetRawText()
        {
            CheckValidInstance();

            return _parent.GetRawValueAsString(_idx);
        }

        internal string GetPropertyRawText()
        {
            CheckValidInstance();

            return _parent.GetPropertyRawValueAsString(_idx);
        }

        /// <summary>
        ///   Compares <paramref name="text" /> to the string value of this element.
        /// </summary>
        /// <param name="text">The text to compare against.</param>
        /// <returns>
        ///   <see langword="true" /> if the string value of this element matches <paramref name="text"/>,
        ///   <see langword="false" /> otherwise.
        /// </returns>
        /// <exception cref="InvalidOperationException">
        ///   This value's <see cref="ValueKind"/> is not <see cref="JsonValueKind.String"/>.
        /// </exception>
        /// <remarks>
        ///   This method is functionally equal to doing an ordinal comparison of <paramref name="text" /> and
        ///   the result of calling <see cref="GetString" />, but avoids creating the string instance.
        /// </remarks>
        public bool ValueEquals(string? text)
        {
            // CheckValidInstance is done in the helper

            if (TokenType == JsonTokenType.Null)
            {
                return text == null;
            }

            return TextEqualsHelper(text.AsSpan(), isPropertyName: false);
        }

        /// <summary>
        ///   Compares the text represented by <paramref name="utf8Text" /> to the string value of this element.
        /// </summary>
        /// <param name="utf8Text">The UTF-8 encoded text to compare against.</param>
        /// <returns>
        ///   <see langword="true" /> if the string value of this element has the same UTF-8 encoding as
        ///   <paramref name="utf8Text" />, <see langword="false" /> otherwise.
        /// </returns>
        /// <exception cref="InvalidOperationException">
        ///   This value's <see cref="ValueKind"/> is not <see cref="JsonValueKind.String"/>.
        /// </exception>
        /// <remarks>
        ///   This method is functionally equal to doing an ordinal comparison of the string produced by UTF-8 decoding
        ///   <paramref name="utf8Text" /> with the result of calling <see cref="GetString" />, but avoids creating the
        ///   string instances.
        /// </remarks>
        public bool ValueEquals(ReadOnlySpan<byte> utf8Text)
        {
            // CheckValidInstance is done in the helper

            if (TokenType == JsonTokenType.Null)
            {
                // This is different than Length == 0, in that it tests true for null, but false for ""
                return utf8Text == default;
            }

            return TextEqualsHelper(utf8Text, isPropertyName: false, shouldUnescape: true);
        }

        /// <summary>
        ///   Compares <paramref name="text" /> to the string value of this element.
        /// </summary>
        /// <param name="text">The text to compare against.</param>
        /// <returns>
        ///   <see langword="true" /> if the string value of this element matches <paramref name="text"/>,
        ///   <see langword="false" /> otherwise.
        /// </returns>
        /// <exception cref="InvalidOperationException">
        ///   This value's <see cref="ValueKind"/> is not <see cref="JsonValueKind.String"/>.
        /// </exception>
        /// <remarks>
        ///   This method is functionally equal to doing an ordinal comparison of <paramref name="text" /> and
        ///   the result of calling <see cref="GetString" />, but avoids creating the string instance.
        /// </remarks>
        public bool ValueEquals(ReadOnlySpan<char> text)
        {
            // CheckValidInstance is done in the helper

            if (TokenType == JsonTokenType.Null)
            {
                // This is different than Length == 0, in that it tests true for null, but false for ""
                return text == default;
            }

            return TextEqualsHelper(text, isPropertyName: false);
        }

        internal bool TextEqualsHelper(ReadOnlySpan<byte> utf8Text, bool isPropertyName, bool shouldUnescape)
        {
            CheckValidInstance();

            return _parent.TextEquals(_idx, utf8Text, isPropertyName, shouldUnescape);
        }

        internal bool TextEqualsHelper(ReadOnlySpan<char> text, bool isPropertyName)
        {
            CheckValidInstance();

            return _parent.TextEquals(_idx, text, isPropertyName);
        }

        ///// <summary>
        /////   Write the element into the provided writer as a JSON value.
        ///// </summary>
        ///// <param name="writer">The writer.</param>
        ///// <exception cref="ArgumentNullException">
        /////   The <paramref name="writer"/> parameter is <see langword="null"/>.
        ///// </exception>
        ///// <exception cref="InvalidOperationException">
        /////   This value's <see cref="ValueKind"/> is <see cref="JsonValueKind.Undefined"/>.
        ///// </exception>
        ///// <exception cref="ObjectDisposedException">
        /////   The parent <see cref="JsonDocument"/> has been disposed.
        ///// </exception>
        //public void WriteTo(Utf8JsonWriter writer)
        //{
        //    if (writer == null)
        //    {
        //        throw new ArgumentNullException(nameof(writer));
        //    }

        //    CheckValidInstance();

        //    _parent.WriteElementTo(_idx, writer);
        //}

        /// <summary>
        ///   Get an enumerator to enumerate the values in the JSON array represented by this JsonElement.
        /// </summary>
        /// <returns>
        ///   An enumerator to enumerate the values in the JSON array represented by this JsonElement.
        /// </returns>
        /// <exception cref="InvalidOperationException">
        ///   This value's <see cref="ValueKind"/> is not <see cref="JsonValueKind.Array"/>.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        ///   The parent <see cref="JsonDocument"/> has been disposed.
        /// </exception>
        public ArrayEnumerator EnumerateArray()
        {
            CheckValidInstance();

            JsonTokenType tokenType = TokenType;

            if (tokenType != JsonTokenType.StartArray)
            {
                //throw ThrowHelper.GetJsonElementWrongTypeException(JsonTokenType.StartArray, tokenType);
                throw new InvalidOperationException();
            }

            return new ArrayEnumerator(this);
        }


        /// <summary>
        ///   Get an enumerator to enumerate the properties in the JSON object represented by this JsonElement.
        /// </summary>
        /// <returns>
        ///   An enumerator to enumerate the properties in the JSON object represented by this JsonElement.
        /// </returns>
        /// <exception cref="InvalidOperationException">
        ///   This value's <see cref="ValueKind"/> is not <see cref="JsonValueKind.Object"/>.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        ///   The parent <see cref="JsonDocument"/> has been disposed.
        /// </exception>
        public ObjectEnumerator EnumerateObject()
        {
            CheckValidInstance();

            JsonTokenType tokenType = TokenType;

            if (tokenType != JsonTokenType.StartObject)
            {
                //throw ThrowHelper.GetJsonElementWrongTypeException(JsonTokenType.StartObject, tokenType);
                throw new InvalidOperationException();
            }

            return new ObjectEnumerator(this);
        }

        /// <summary>
        ///   Gets a string representation for the current value appropriate to the value type.
        /// </summary>
        /// <remarks>
        ///   <para>
        ///     For JsonElement built from <see cref="JsonDocument"/>:
        ///   </para>
        ///
        ///   <para>
        ///     For <see cref="JsonValueKind.Null"/>, <see cref="string.Empty"/> is returned.
        ///   </para>
        ///
        ///   <para>
        ///     For <see cref="JsonValueKind.True"/>, <see cref="bool.TrueString"/> is returned.
        ///   </para>
        ///
        ///   <para>
        ///     For <see cref="JsonValueKind.False"/>, <see cref="bool.FalseString"/> is returned.
        ///   </para>
        ///
        ///   <para>
        ///     For <see cref="JsonValueKind.String"/>, the value of <see cref="GetString"/>() is returned.
        ///   </para>
        ///
        ///   <para>
        ///     For other types, the value of <see cref="GetRawText"/>() is returned.
        ///   </para>
        /// </remarks>
        /// <returns>
        ///   A string representation for the current value appropriate to the value type.
        /// </returns>
        /// <exception cref="ObjectDisposedException">
        ///   The parent <see cref="JsonDocument"/> has been disposed.
        /// </exception>
        //public override string? ToString()
        //{
        //    switch (TokenType)
        //    {
        //        case JsonTokenType.None:
        //        case JsonTokenType.Null:
        //            return string.Empty;
        //        case JsonTokenType.True:
        //            return bool.TrueString;
        //        case JsonTokenType.False:
        //            return bool.FalseString;
        //        case JsonTokenType.Number:
        //        case JsonTokenType.StartArray:
        //        case JsonTokenType.StartObject:
        //            {
        //                // null parent should have hit the None case
        //                Debug.Assert(_parent != null);
        //                return ((JwtPayloadDocument)_parent).GetRawValueAsString(_idx);
        //            }
        //        case JsonTokenType.String:
        //            return GetString();
        //        case JsonTokenType.Comment:
        //        case JsonTokenType.EndArray:
        //        case JsonTokenType.EndObject:
        //        default:
        //            Debug.Fail($"No handler for {nameof(JsonTokenType)}.{TokenType}");
        //            return string.Empty;
        //    }
        //}

        /// <summary>
        ///   Get a JsonElement which can be safely stored beyond the lifetime of the
        ///   original <see cref="JsonDocument"/>.
        /// </summary>
        /// <returns>
        ///   A JsonElement which can be safely stored beyond the lifetime of the
        ///   original <see cref="JsonDocument"/>.
        /// </returns>
        /// <remarks>
        ///   <para>
        ///     If this JsonElement is itself the output of a previous call to Clone, or
        ///     a value contained within another JsonElement which was the output of a previous
        ///     call to Clone, this method results in no additional memory allocation.
        ///   </para>
        /// </remarks>
        //public JwtElement Clone()
        //{
        //    CheckValidInstance();

        //    if (!_parent.IsDisposable)
        //    {
        //        return this;
        //    }

        //    return _parent.CloneElement(_idx);
        //}

        private void CheckValidInstance()
        {
            if (_parent == null)
            {
                throw new InvalidOperationException();
            }
        }

        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private string DebuggerDisplay => $"ValueKind = {ValueKind} : \"{ToString()}\"";

        internal static JsonValueKind ToValueKind(JsonTokenType tokenType)
        {
            switch (tokenType)
            {
                case JsonTokenType.None:
                    return JsonValueKind.Undefined;
                case JsonTokenType.StartArray:
                    return JsonValueKind.Array;
                case JsonTokenType.StartObject:
                    return JsonValueKind.Object;
                case JsonTokenType.String:
                case JsonTokenType.Number:
                case JsonTokenType.True:
                case JsonTokenType.False:
                case JsonTokenType.Null:
                    // This is the offset between the set of literals within JsonValueType and JsonTokenType
                    // Essentially: JsonTokenType.Null - JsonValueType.Null
                    return (JsonValueKind)((byte)tokenType - 4);
                default:
                    Debug.Fail($"No mapping for token type {tokenType}");
                    return JsonValueKind.Undefined;
            }
        }
    }
}