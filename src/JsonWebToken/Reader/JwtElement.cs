using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>Represents a specific JWT value within a <see cref="JwtDocument"/>.</summary>
    // Based on https://github.com/dotnet/runtime/blob/master/src/libraries/System.Text.Json/src/System/Text/Json/Document/JsonElement.cs
    [DebuggerDisplay("{DebuggerDisplay,nq}")]
    public readonly struct JwtElement
    {
        private readonly JwtDocument _parent;
        private readonly int _idx;

        internal JwtElement(JwtDocument parent, int idx)
        {
            // parent is usually not null, but the Current property
            // on the enumerators (when initialized as `default`) can
            // get here with a null.
            Debug.Assert(idx >= 0);
            Debug.Assert(parent != null);

            _parent = parent;
            _idx = idx;
        }

        /// <summary>Defines whether the current <see cref="JwtElement"/> is empty</summary>
        public bool IsEmpty => _parent is null;

        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private JsonTokenType TokenType => _parent is null ? JsonTokenType.None : _parent.GetJsonTokenType(_idx);

        /// <summary>The <see cref="JsonValueKind"/> that the value is.</summary>
        public JsonValueKind ValueKind => ToValueKind(TokenType);

        /// <summary>Get the value at a specified index when the current value is a <see cref="JsonValueKind.Array"/>.</summary>
        /// <exception cref="InvalidOperationException">
        ///   This value's <see cref="ValueKind"/> is not <see cref="JsonValueKind.Array"/>.
        /// </exception>
        /// <exception cref="IndexOutOfRangeException">
        ///   <paramref name="index"/> is not in the range [0, <see cref="GetArrayLength"/>()).
        /// </exception>
        public JwtElement this[int index]
        {
            get
            {
                if (_parent != null)
                {
                    return _parent.GetArrayIndexElement(_idx, index);
                }

                throw new IndexOutOfRangeException();
            }
        }

        /// <summary>
        ///   Get the value for a specified key when the current value is a
        ///   <see cref="JsonValueKind.Object"/>.
        /// </summary>
        /// <exception cref="InvalidOperationException">
        ///   This value's <see cref="ValueKind"/> is not <see cref="JsonValueKind.Object"/>.
        /// </exception>
        /// <exception cref="IndexOutOfRangeException">
        ///   <paramref name="key"/> is not a valid property name.
        /// </exception>
        public JwtElement this[string key]
        {
            get
            {
                if (_parent != null)
                {
                    foreach (var item in EnumerateObject())
                    {
                        if (item.NameEquals(key))
                        {
                            return item.Value;
                        }
                    }
                }

                throw new KeyNotFoundException();
            }
        }

        /// <summary>
        ///   Get the value for a specified key when the current value is a
        ///   <see cref="JsonValueKind.Object"/>.
        /// </summary>
        /// <exception cref="InvalidOperationException">
        ///   This value's <see cref="ValueKind"/> is not <see cref="JsonValueKind.Object"/>.
        /// </exception>
        /// <exception cref="IndexOutOfRangeException">
        ///   <paramref name="key"/> is not a valid property name.
        /// </exception>
        public JwtElement this[ReadOnlySpan<byte> key]
        {
            get
            {
                if (_parent != null)
                {
                    foreach (var item in EnumerateObject())
                    {
                        if (item.NameEquals(key))
                        {
                            return item.Value;
                        }
                    }
                }

                throw new KeyNotFoundException();
            }
        }

        /// <summary>
        ///   Get the number of values contained within the current array value.
        /// </summary>
        /// <returns>The number of values contained within the current array value.</returns>
        /// <exception cref="InvalidOperationException">
        ///   This value's <see cref="ValueKind"/> is not <see cref="JsonValueKind.Array"/>.
        /// </exception>
        public int GetArrayLength() => _parent is null ? 0 : _parent.GetArrayLength(_idx);

        /// <summary>Get the number of members contained within the current object value.</summary>
        /// <returns>The number of members contained within the current object value.</returns>
        /// <exception cref="InvalidOperationException">
        ///   This value's <see cref="ValueKind"/> is not <see cref="JsonValueKind.Object"/>.
        /// </exception>
        public int GetMemberCount()
            => _parent is null ? 0 : _parent.GetMemberCount(_idx);

        internal bool TryGetProperty(string propertyName, out JwtElement value)
            => TryGetProperty(propertyName.AsSpan(), out value);

        internal bool TryGetProperty(ReadOnlySpan<char> propertyName, out JwtElement value)
            => _parent.TryGetNamedPropertyValue(propertyName, out value);

        internal bool TryGetProperty(ReadOnlySpan<byte> utf8PropertyName, out JwtElement value)
            => _parent.TryGetNamedPropertyValue(utf8PropertyName, out value);

        /// <summary>Gets the value of the element as a <see cref="bool"/>.</summary>
        /// <remarks>This method does not parse the contents of a JSON string value.</remarks>
        /// <returns>The value of the element as a <see cref="bool"/>.</returns>
        /// <exception cref="InvalidOperationException">
        ///   This value's <see cref="ValueKind"/> is neither <see cref="JsonValueKind.True"/> or
        ///   <see cref="JsonValueKind.False"/>.
        /// </exception>
        public bool GetBoolean()
        {
            JsonTokenType type = TokenType;
            return
                type == JsonTokenType.True || (type == JsonTokenType.False ? false :
                throw ThrowHelper.CreateInvalidOperationException_NotSupportedJsonType(type));
        }

        /// <summary>Gets the value of the element as a <see cref="string"/>.</summary>
        /// <remarks>This method does not create a string representation of values other than JSON strings.</remarks>
        /// <returns>The value of the element as a <see cref="string"/>.</returns>
        /// <exception cref="InvalidOperationException">
        ///   This value's <see cref="ValueKind"/> is neither <see cref="JsonValueKind.String"/> nor <see cref="JsonValueKind.Null"/>.
        /// </exception>
        public string? GetString()
        {
            if (_parent is null)
            {
                return null;
            }

            return _parent.GetString(_idx, JsonTokenType.String);
        }

        /// <summary>Gets the original input data backing this value, returning it as an array of <see cref="string"/>.</summary>
        /// <returns>The original input data backing this value, returning it as an array of <see cref="string"/>.</returns>
        public string?[]? GetStringArray()
            => _parent.GetStringArray(_idx);

        /// <summary>Parses the UTF-8 encoded text representing a single JSON value into an instance of the type specified by a generic type parameter.</summary>
        /// <returns>The original input data backing this value, returning it as a <see cref="string"/>.</returns>
        public TValue? Deserialize<TValue>(JsonSerializerOptions? options = null)
            where TValue : class
            => _parent.Deserialize<TValue>(_idx, options);

        /// <summary>Attempts to represent the current JSON number as a <see cref="long"/>.</summary>
        /// <param name="value">Receives the value.</param>
        /// <remarks>This method does not parse the contents of a JSON string value.</remarks>
        /// <returns>
        ///   <see langword="true"/> if the number can be represented as a <see cref="long"/>,
        ///   <see langword="false"/> otherwise.
        /// </returns>
        /// <exception cref="InvalidOperationException">
        ///   This value's <see cref="ValueKind"/> is not <see cref="JsonValueKind.Number"/>.
        /// </exception>
        public bool TryGetInt64(out long value)
        {
            if (_parent is null)
            {
                value = 0L;
                return false;
            }

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
        public long GetInt64()
        {
            if (TryGetInt64(out long value))
            {
                return value;
            }

            throw ThrowHelper.CreateFormatException_MalformedJson();
        }

        /// <summary>Attempts to represent the current JSON number as a <see cref="double"/>.</summary>
        /// <param name="value">Receives the value.</param>
        /// <remarks>
        ///   <para>
        ///     This method does not parse the contents of a JSON string value.
        ///   </para>
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
        public bool TryGetDouble(out double value)
        {
            if (_parent is null)
            {
                value = 0;
                return false;
            }

            return _parent.TryGetValue(_idx, out value);
        }

        /// <summary>Attempts to represent the current JSON object as a <see cref="JwtDocument"/>.</summary>
        /// <param name="value">Receives the value.</param>
        /// <returns>
        ///   <see langword="true"/> if the JSON object can be represented as a <see cref="JwtDocument"/>,
        ///   <see langword="false"/> otherwise.
        /// </returns>
        /// <exception cref="InvalidOperationException">
        ///   This value's <see cref="ValueKind"/> is not <see cref="JsonValueKind.Object"/>.
        /// </exception>
        public bool TryGetJsonDocument([NotNullWhen(true)] out JsonDocument? value)
        {
            if (_parent is null)
            {
#if NET5_0_OR_GREATER
                Unsafe.SkipInit(out value);
#else
                value = default;
#endif
                return false;
            }

            return _parent.TryGetValue(_idx, out value);
        }

        /// <summary>Gets the current JSON number as a <see cref="double"/>.</summary>
        /// <returns>The current JSON number as a <see cref="double"/>.</returns>
        /// <remarks>
        ///   <para>
        ///     This method does not parse the contents of a JSON string value.
        ///   </para>
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
        public double GetDouble()
        {
            if (TryGetDouble(out double value))
            {
                return value;
            }

            throw ThrowHelper.CreateFormatException_MalformedJson();
        }

        /// <summary>Gets the current JSON object as a <see cref="JwtDocument"/>.</summary>
        /// <returns>The current JSON object as a <see cref="JwtDocument"/>.</returns>
        /// <remarks>
        ///   <para>
        ///     This method does not parse the contents of a JSON string value.
        ///   </para>
        /// </remarks>
        /// <exception cref="InvalidOperationException">
        ///   This value's <see cref="ValueKind"/> is not <see cref="JsonValueKind.Object"/>.
        /// </exception>
        /// <exception cref="FormatException">
        ///   The value cannot be represented as a <see cref="JwtDocument"/>.
        /// </exception>
        public JsonDocument GetJsonDocument()
        {
            if (TryGetJsonDocument(out JsonDocument? value))
            {
                return value;
            }

            throw ThrowHelper.CreateFormatException_MalformedJson();
        }

        internal string GetPropertyName()
            => _parent is null ? string.Empty : _parent.GetNameOfPropertyValue(_idx);

        /// <summary>Gets the original input data backing this value, returning it as a <see cref="string"/>.</summary>
        /// <returns>The original input data backing this value, returning it as a <see cref="string"/>.</returns>
        public string GetRawText()
            => _parent is null ? string.Empty : _parent.GetRawValueAsString(_idx);

        /// <summary>Gets the original input data backing this value, returning it as a <see cref="ReadOnlyMemory{T}"/> of byte.</summary>
        /// <returns>The original input data backing this value, returning it as a <see cref="ReadOnlyMemory{T}"/> of byte.</returns>
        public ReadOnlyMemory<byte> GetRawValue()
            => _parent is null ? default : _parent.GetRawValue(_idx);

        internal string GetPropertyRawText()
            => _parent is null ? string.Empty : _parent.GetPropertyRawValueAsString(_idx);

        /// <summary>Compares <paramref name="text" /> to the string value of this element.</summary>
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
            => TokenType == JsonTokenType.Null
                ? text is null
                : TextEqualsHelper(text.AsSpan(), isPropertyName: false);

        /// <summary>Compares the text represented by <paramref name="utf8Text" /> to the string value of this element.</summary>
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
        ///   <paramref name="utf8Text" /> with the result of <see cref="GetString" />, but avoids creating the
        ///   string instances.
        /// </remarks>
        public bool ValueEquals(ReadOnlySpan<byte> utf8Text)
        {
            if (TokenType == JsonTokenType.Null | _parent is null)
            {
                // This is different than Length == 0, in that it tests true for null, but false for ""
                return utf8Text == default;
            }

            return TextEqualsHelper(utf8Text, isPropertyName: false, shouldUnescape: true);
        }

        /// <summary>Compares <paramref name="text" /> to the string value of this element.</summary>
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
            if (TokenType == JsonTokenType.Null)
            {
                // This is different than Length == 0, in that it tests true for null, but false for ""
                return text == default;
            }

            return TextEqualsHelper(text, isPropertyName: false);
        }

        internal bool TextEqualsHelper(ReadOnlySpan<byte> utf8Text, bool isPropertyName, bool shouldUnescape)
            => _parent is null ? utf8Text == default : _parent.TextEquals(_idx, utf8Text, isPropertyName, shouldUnescape);

        internal bool TextEqualsHelper(ReadOnlySpan<char> text, bool isPropertyName)
            => _parent is null ? text == default : _parent.TextEquals(_idx, text, isPropertyName);

        /// <summary>Get an enumerator to enumerate the values in the JSON array represented by this JsonElement.</summary>
        /// <returns>An enumerator to enumerate the values in the JSON array represented by this JsonElement.</returns>
        /// <exception cref="InvalidOperationException">
        ///   This value's <see cref="ValueKind"/> is not <see cref="JsonValueKind.Array"/>.
        /// </exception>
        public ArrayEnumerator EnumerateArray()
        {
            JsonTokenType tokenType = TokenType;
            if (tokenType != JsonTokenType.StartArray)
            {
                ThrowHelper.ThrowJsonElementWrongType_InvalidOperationException(JsonTokenType.StartArray, tokenType);
            }

            return new ArrayEnumerator(this);
        }

        /// <summary>Get an enumerator to enumerate the values in the JSON array represented by this JsonElement.</summary>
        /// <returns>An enumerator to enumerate the values in the JSON array represented by this JsonElement.</returns>
        /// <exception cref="InvalidOperationException">
        ///   This value's <see cref="ValueKind"/> is not <see cref="JsonValueKind.Array"/>.
        /// </exception>
        public ArrayEnumerator<T> EnumerateArray<T>()
        {
            JsonTokenType tokenType = TokenType;
            if (tokenType != JsonTokenType.StartArray)
            {
                ThrowHelper.ThrowJsonElementWrongType_InvalidOperationException(JsonTokenType.StartArray, tokenType);
            }

            return new ArrayEnumerator<T>(this);
        }

        /// <summary>Get an enumerator to enumerate the properties in the JSON object represented by this JsonElement.</summary>
        /// <returns>An enumerator to enumerate the properties in the JSON object represented by this JsonElement.</returns>
        /// <exception cref="InvalidOperationException">This value's <see cref="ValueKind"/> is not <see cref="JsonValueKind.Object"/>.</exception>
        public ObjectEnumerator EnumerateObject()
        {
            JsonTokenType tokenType = TokenType;
            if (tokenType != JsonTokenType.StartObject)
            {
                ThrowHelper.ThrowJsonElementWrongType_InvalidOperationException(JsonTokenType.StartObject, tokenType);
            }

            return new ObjectEnumerator(this);
        }

        /// <summary>Determines whether the <see cref="JwtElement"/> contains the specified property.</summary>
        public bool ContainsKey(string propertyName)
        {
            var value = GetRawValue();
            int count = GetMemberCount();

            var reader = new Utf8JsonReader(value.Span);
            if (reader.Read())
            {
                JsonTokenType tokenType = reader.TokenType;
                if (tokenType == JsonTokenType.StartObject)
                {
                    while (reader.Read())
                    {
                        tokenType = reader.TokenType;
                        if (tokenType == JsonTokenType.EndObject)
                        {
                            break;
                        }
                        else if (tokenType != JsonTokenType.PropertyName)
                        {
                            break;
                        }

                        if (reader.ValueTextEquals(propertyName))
                        {
                            return true;
                        }

                        if (count-- == 0)
                        {
                            break;
                        }

                        reader.Read();
                    }
                }
            }

            return false;
        }

        /// <summary>Determines whether the <see cref="JwtElement"/> contains the specified property.</summary>
        public bool ContainsKey(ReadOnlySpan<byte> propertyName)
        {
            var value = GetRawValue();
            int count = GetMemberCount();

            var reader = new Utf8JsonReader(value.Span);
            if (reader.Read())
            {
                JsonTokenType tokenType = reader.TokenType;
                if (tokenType == JsonTokenType.StartObject)
                {
                    while (reader.Read())
                    {
                        tokenType = reader.TokenType;
                        if (tokenType == JsonTokenType.EndObject)
                        {
                            break;
                        }
                        else if (tokenType != JsonTokenType.PropertyName)
                        {
                            break;
                        }

                        if (reader.ValueTextEquals(propertyName))
                        {
                            return true;
                        }

                        if (count-- == 0)
                        {
                            break;
                        }

                        reader.Read();
                    }
                }
            }

            return false;
        }

        /// <inheritdoc/>
        public override string? ToString()
        {
            switch (TokenType)
            {
                case JsonTokenType.None:
                case JsonTokenType.Null:
                    return string.Empty;
                case JsonTokenType.True:
                    return bool.TrueString;
                case JsonTokenType.False:
                    return bool.FalseString;
                case JsonTokenType.Number:
                case JsonTokenType.StartArray:
                case JsonTokenType.StartObject:
                    return _parent.GetRawValueAsString(_idx);
                case JsonTokenType.String:
                    return GetString();
                case JsonTokenType.Comment:
                case JsonTokenType.EndArray:
                case JsonTokenType.EndObject:
                default:
                    Debug.Fail($"No handler for {nameof(JsonTokenType)}.{TokenType}");
                    return string.Empty;
            }
        }

        /// <summary>Get a JwtElement which can be safely stored beyond the lifetime of theoriginal <see cref="JwtDocument"/>.</summary>
        /// <remarks>
        ///     If this JwtElement is itself the output of a previous call to Clone, or
        ///     a value contained within another JwtElement which was the output of a previous
        ///     call to Clone, this method results in no additional memory allocation.
        /// </remarks>
        public JwtElement Clone()
        {
            if (!_parent.IsDisposable)
            {
                return this;
            }

            return _parent.CloneElement(_idx);
        }

        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private string DebuggerDisplay => $"ValueKind = {ValueKind} : \"{ToString()}\"";

        internal int Idx => _idx;

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

        /// <summary>An enumerable and enumerator for the properties of a JSON object.</summary>
        [DebuggerDisplay("{Current,nq}")]
        public struct ObjectEnumerator
        {
            private int _curIdx;
            private readonly JwtDocument _document;
            private readonly int _endIdxOrVersion;

            internal ObjectEnumerator(JwtElement target)
            {
                _curIdx = -1;

                var value = target.GetRawValue();
                int count = target.GetMemberCount();
                if (!TryParse(value, target.GetMemberCount(), out _document!))
                {
                    ThrowHelper.ThrowFormatException_MalformedJson();
                }

                Debug.Assert(target.TokenType == JsonTokenType.StartObject);
                _endIdxOrVersion = count * JsonRow.Size * 2;
            }

            /// <inheritdoc />
            public JwtMemberElement Current
            {
                get
                {
                    if (_curIdx < 0)
                    {
                        return default;
                    }

                    return new JwtMemberElement(new JwtElement(_document, _curIdx));
                }
            }

            /// <summary>Returns an enumerator that iterates the properties of an object.</summary>
            /// <remarks>
            ///   The enumerator will enumerate the properties in the order they are
            ///   declared, and when an object has multiple definitions of a single
            ///   property they will all individually be returned (each in the order
            ///   they appear in the content).
            /// </remarks>
            public ObjectEnumerator GetEnumerator()
            {
                ObjectEnumerator ator = this;
                ator._curIdx = -1;
                return ator;
            }

            /// <inheritdoc />
            public void Dispose()
            {
                _curIdx = _endIdxOrVersion;
            }

            /// <inheritdoc />
            public void Reset()
            {
                _curIdx = -1;
            }

            /// <inheritdoc />
            public bool MoveNext()
            {
                if (_curIdx >= _endIdxOrVersion)
                {
                    return false;
                }

                if (_curIdx < 0)
                {
                    _curIdx = 0;
                }
                else
                {
                    _curIdx += JsonRow.Size;
                }

                // _curIdx is now pointing at a property name, move one more to get the value
                _curIdx += JsonRow.Size;

                return _curIdx < _endIdxOrVersion;
            }

            private static bool TryParse(ReadOnlyMemory<byte> utf8Array, int count, out JwtDocument? document)
            {
                ReadOnlySpan<byte> utf8JsonSpan = utf8Array.Span;
                var database = new JsonMetadata(count * JsonRow.Size);

                var reader = new Utf8JsonReader(utf8JsonSpan);
                if (reader.Read())
                {
                    JsonTokenType tokenType = reader.TokenType;
                    if (tokenType == JsonTokenType.StartObject)
                    {
                        while (reader.Read())
                        {
                            tokenType = reader.TokenType;
                            int tokenStart = (int)reader.TokenStartIndex;

                            if (tokenType == JsonTokenType.EndObject)
                            {
                                break;
                            }
                            else if (tokenType != JsonTokenType.PropertyName)
                            {
                                goto Error;
                            }

                            // Adding 1 to skip the start quote will never overflow
                            Debug.Assert(tokenStart < int.MaxValue);

                            database.Append(JsonTokenType.PropertyName, tokenStart + 1, reader.ValueSpan.Length);

                            reader.Read();
                            tokenType = reader.TokenType;
                            tokenStart = (int)reader.TokenStartIndex;

                            // Since the input payload is contained within a Span,
                            // token start index can never be larger than int.MaxValue (i.e. utf8JsonSpan.Length).
                            Debug.Assert(reader.TokenStartIndex <= int.MaxValue);
                            if (tokenType == JsonTokenType.String)
                            {
                                // Adding 1 to skip the start quote will never overflow
                                Debug.Assert(tokenStart < int.MaxValue);
                                database.Append(JsonTokenType.String, tokenStart + 1, reader.ValueSpan.Length);
                            }
                            else if (tokenType == JsonTokenType.Number)
                            {
                                database.Append(JsonTokenType.Number, tokenStart, reader.ValueSpan.Length);
                            }
                            else if (tokenType == JsonTokenType.StartObject)
                            {
                                int itemCount = Utf8JsonReaderHelper.SkipObject(ref reader);
                                int tokenEnd = (int)reader.TokenStartIndex;
                                int index = database.Length;
                                database.Append(JsonTokenType.StartObject, tokenStart, tokenEnd - tokenStart + 1);
                                database.SetNumberOfRows(index, itemCount);
                            }
                            else if (tokenType == JsonTokenType.StartArray)
                            {
                                int itemCount = Utf8JsonReaderHelper.SkipArray(ref reader);

                                int index = database.Length;
                                int tokenEnd = (int)reader.TokenStartIndex;
                                database.Append(JsonTokenType.StartArray, tokenStart, tokenEnd - tokenStart + 1);
                                database.SetNumberOfRows(index, itemCount);
                            }
                            else
                            {
                                Debug.Assert(tokenType >= JsonTokenType.True && tokenType <= JsonTokenType.Null);
                                database.Append(tokenType, tokenStart, reader.ValueSpan.Length);
                            }
                        }
                    }
                }

                Debug.Assert(reader.BytesConsumed == utf8JsonSpan.Length);
                database.CompleteAllocations();

                document = new JwtDocument(utf8Array, database, null);
                return true;

            Error:
#if NET5_0_OR_GREATER
                Unsafe.SkipInit(out document);
#else
                document = default;
#endif
                return false;
            }
        }

        /// <summary>An enumerable and enumerator for the contents of a JSON array.</summary>
        [DebuggerDisplay("{Current,nq}")]
        public struct ArrayEnumerator
        {
            private int _curIdx;
            private readonly JwtDocument _document;
            private readonly int _endIdxOrVersion;

            internal ArrayEnumerator(JwtElement target)
            {
                _curIdx = -1;

                var value = target.GetRawValue();
                if (!TryParse(value, target.GetArrayLength(), out _document!))
                {
                    ThrowHelper.ThrowFormatException_MalformedJson();
                }

                Debug.Assert(target.TokenType == JsonTokenType.StartArray);
                _endIdxOrVersion = value.Length;
            }

            /// <inheritdoc />
            public JwtElement Current
            {
                get
                {
                    if (_curIdx < 0)
                    {
                        return default;
                    }

                    return new JwtElement(_document, _curIdx);
                }
            }

            /// <summary>Returns an enumerator that iterates through a collection.</summary>
            public ArrayEnumerator GetEnumerator()
            {
                ArrayEnumerator ator = this;
                ator._curIdx = -1;
                return ator;
            }

            /// <inheritdoc />
            public void Dispose()
            {
                _curIdx = _endIdxOrVersion;
                _document?.Dispose();
            }

            /// <inheritdoc />
            public void Reset()
            {
                _curIdx = -1;
            }

            /// <inheritdoc />
            public bool MoveNext()
            {
                if (_curIdx >= _endIdxOrVersion)
                {
                    return false;
                }

                if (_curIdx < 0)
                {
                    _curIdx = 0;
                }
                else
                {
                    _curIdx += JsonRow.Size;
                }

                return _curIdx < _endIdxOrVersion;
            }

            private static bool TryParse(ReadOnlyMemory<byte> utf8Array, int count, out JwtDocument? document)
            {
                ReadOnlySpan<byte> utf8JsonSpan = utf8Array.Span;
                var database = new JsonMetadata(count * JsonRow.Size);

                var reader = new Utf8JsonReader(utf8JsonSpan);
                if (reader.Read())
                {
                    JsonTokenType tokenType = reader.TokenType;
                    if (tokenType == JsonTokenType.StartArray)
                    {
                        while (reader.Read())
                        {
                            tokenType = reader.TokenType;
                            int tokenStart = (int)reader.TokenStartIndex;

                            if (tokenType == JsonTokenType.EndArray)
                            {
                                break;
                            }
                            else if (tokenType == JsonTokenType.PropertyName)
                            {
                                goto Error;
                            }

                            // Since the input payload is contained within a Span,
                            // token start index can never be larger than int.MaxValue (i.e. utf8JsonSpan.Length).
                            Debug.Assert(reader.TokenStartIndex <= int.MaxValue);
                            if (tokenType == JsonTokenType.String)
                            {
                                // Adding 1 to skip the start quote will never overflow
                                Debug.Assert(tokenStart < int.MaxValue);
                                database.Append(JsonTokenType.String, tokenStart + 1, reader.ValueSpan.Length);
                            }
                            else if (tokenType == JsonTokenType.Number)
                            {
                                database.Append(JsonTokenType.Number, tokenStart, reader.ValueSpan.Length);
                            }
                            else if (tokenType == JsonTokenType.StartObject)
                            {
                                int itemCount = Utf8JsonReaderHelper.SkipObject(ref reader);
                                int tokenEnd = (int)reader.TokenStartIndex;
                                int index = database.Length;
                                database.Append(JsonTokenType.StartObject, tokenStart, tokenEnd - tokenStart + 1);
                                database.SetNumberOfRows(index, itemCount);
                            }
                            else if (tokenType == JsonTokenType.StartArray)
                            {
                                int itemCount = Utf8JsonReaderHelper.SkipArray(ref reader);

                                int index = database.Length;
                                int tokenEnd = (int)reader.TokenStartIndex;
                                database.Append(JsonTokenType.StartArray, tokenStart, tokenEnd - tokenStart + 1);
                                database.SetNumberOfRows(index, itemCount);
                            }
                            else
                            {
                                Debug.Assert(tokenType >= JsonTokenType.True && tokenType <= JsonTokenType.Null);
                                database.Append(tokenType, tokenStart, reader.ValueSpan.Length);
                            }
                        }
                    }
                }

                Debug.Assert(reader.BytesConsumed == utf8JsonSpan.Length);
                database.CompleteAllocations();

                document = new JwtDocument(utf8Array, database, null);
                return true;

            Error:
#if NET5_0_OR_GREATER
                Unsafe.SkipInit(out document);
#else
                document = default;
#endif
                return false;
            }
        }

        /// <summary>An enumerable and enumerator for the contents of a JSON array.</summary>
        [DebuggerDisplay("{Current,nq}")]
        public struct ArrayEnumerator<T>
        {
            private int _curIdx;
            private readonly JwtDocument _document;
            private readonly int _endIdxOrVersion;

            internal ArrayEnumerator(JwtElement target)
            {
                if (typeof(T) != typeof(string) && typeof(T) != typeof(long) && typeof(T) != typeof(double))
                {
                    throw new NotSupportedException();
                }

                _curIdx = -1;

                var value = target.GetRawValue();
                if (!TryParse(value, target.GetArrayLength(), out _document!))
                {
                    ThrowHelper.ThrowFormatException_MalformedJson();
                }

                Debug.Assert(target.TokenType == JsonTokenType.StartArray);
                _endIdxOrVersion = value.Length;
            }

            /// <inheritdoc />
            public JwtElement Current
            {
                get
                {
                    if (_curIdx < 0)
                    {
                        return default;
                    }

                    return new JwtElement(_document, _curIdx);
                }
            }

            /// <summary>Returns an enumerator that iterates through a collection.</summary>
            public ArrayEnumerator<T> GetEnumerator()
            {
                ArrayEnumerator<T> ator = this;
                ator._curIdx = -1;
                return ator;
            }

            /// <inheritdoc />
            public void Dispose()
            {
                _curIdx = _endIdxOrVersion;
                _document?.Dispose();
            }

            /// <inheritdoc />
            public void Reset()
            {
                _curIdx = -1;
            }

            /// <inheritdoc />
            public bool MoveNext()
            {
                if (_curIdx >= _endIdxOrVersion)
                {
                    return false;
                }

                if (_curIdx < 0)
                {
                    _curIdx = 0;
                }
                else
                {
                    _curIdx += JsonRow.Size;
                }

                return _curIdx < _endIdxOrVersion;
            }

            private static bool TryParse(ReadOnlyMemory<byte> utf8Array, int count, out JwtDocument? document)
            {
                ReadOnlySpan<byte> utf8JsonSpan = utf8Array.Span;
                var database = new JsonMetadata(count * JsonRow.Size);

                var reader = new Utf8JsonReader(utf8JsonSpan);
                if (reader.Read())
                {
                    JsonTokenType tokenType = reader.TokenType;
                    if (tokenType == JsonTokenType.StartArray)
                    {
                        while (reader.Read())
                        {
                            tokenType = reader.TokenType;
                            int tokenStart = (int)reader.TokenStartIndex;

                            if (tokenType == JsonTokenType.EndArray)
                            {
                                break;
                            }

                            Debug.Assert(reader.TokenStartIndex <= int.MaxValue);
                            if (typeof(T) == typeof(string))
                            {
                                if (tokenType == JsonTokenType.String)
                                {
                                    Debug.Assert(tokenStart < int.MaxValue);
                                    database.Append(JsonTokenType.String, tokenStart + 1, reader.ValueSpan.Length);
                                }
                                else
                                {
                                    goto Error;
                                }
                            }
                            else if (typeof(T) == typeof(long) || typeof(T) == typeof(double))
                            {
                                if (tokenType == JsonTokenType.Number)
                                {
                                    Debug.Assert(tokenStart < int.MaxValue);
                                    database.Append(JsonTokenType.Number, tokenStart + 1, reader.ValueSpan.Length);
                                }
                                else
                                {
                                    goto Error;
                                }
                            }
                            else
                            {
                                goto Error;
                            }
                        }
                    }
                }

                Debug.Assert(reader.BytesConsumed == utf8JsonSpan.Length);
                database.CompleteAllocations();

                document = new JwtDocument(utf8Array, database, null);
                return true;

            Error:
#if NET5_0_OR_GREATER
                Unsafe.SkipInit(out document);
#else
                document = default;
#endif
                return false;
            }
        }

        private void CheckValidInstance()
        {
            if (_parent is null)
            {
                throw new InvalidOperationException();
            }
        }
    }
}