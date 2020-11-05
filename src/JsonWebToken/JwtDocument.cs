using System;
using System.Buffers;
using System.Buffers.Text;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading;
using JsonWebToken.Internal;

namespace JsonWebToken
{
    /// <summary>
    /// Defines an abstract class for representing a JWT.
    /// </summary>
    [DebuggerDisplay("{DebuggerDisplay(),nq}")]
    public abstract class JwtDescriptorX
    {
        private Jwk? _key;
        private JwtHeaderX _header;

        /// <summary>
        /// Initializes a new instance of <see cref="JwtDescriptor"/>.
        /// </summary>
        protected JwtDescriptorX()
        {
            _header = new JwtHeaderX();
        }

        /// <summary>
        /// Gets the parameters header.
        /// </summary>
        public JwtHeaderX Header
        {
            get => _header;
            set
            {
                if (value is null)
                {
                    ThrowHelper.ThrowArgumentNullException(ExceptionArgument.value);
                }

                _header.CopyTo(value);
                _header = value;
            }
        }

        /// <summary>
        /// Gets the <see cref="Jwk"/> used.
        /// </summary>
        protected Jwk Key
        {
            get => _key ?? Jwk.Empty;
            set
            {
                if (value is null)
                {
                    ThrowHelper.ThrowArgumentNullException(ExceptionArgument.value);
                }

                _key = value;
                if (value.Kid != null)
                {
                    Header.Add(HeaderParameters.Kid, value.Kid);
                }

                OnKeyChanged(value);
            }
        }

        /// <summary>
        /// Called when the key is set.
        /// </summary>
        /// <param name="key"></param>
        protected abstract void OnKeyChanged(Jwk? key);

        ///// <summary>
        ///// Sets the key identifier header parameter.
        ///// </summary>
        //public void AddKid(string? value)
        //    => Header.Add(HeaderParameters.KidUtf8, value);

        ///// <summary>
        ///// Gets or sets the JWKS URL header parameter.
        ///// </summary>
        //public void AddJku(string? value)
        //    => Header.Add(HeaderParameters.JkuUtf8, value);

        ///// <summary>
        ///// Gets or sets the X509 URL header parameter.
        ///// </summary>
        //public void AddX5u(string? value)
        //    => Header.Add(HeaderParameters.X5uUtf8, value);

        ///// <summary>
        ///// Gets or sets the X509 certification chain header.
        ///// </summary>
        //public void AddX5c(string?[] value)
        //    => Header.Add(HeaderParameters.X5cUtf8, value);

        ///// <summary>
        ///// Gets or sets the X509 certificate SHA-1 thumbprint header parameter.
        ///// </summary>
        //public void AddX5t(string? value)
        //    => Header.Add(HeaderParameters.X5tUtf8, value);

        ///// <summary>
        ///// Gets or sets the JWT type 'typ' header parameter.
        ///// </summary>
        //public void AddTyp(string? value)
        //    => Header.Add(HeaderParameters.TypUtf8, value);

        ///// <summary>
        ///// Gets or sets the JWT type 'typ' header parameter.
        ///// </summary>
        //public void AddTyp(ReadOnlySpan<byte> value)
        //    => Header.Add(HeaderParameters.TypUtf8, value);

        ///// <summary>
        ///// Gets or sets the content type header parameter.
        ///// </summary>
        //public void AddCty(string? value)
        //    => Header.Add(HeaderParameters.CtyUtf8, value);

        ///// <summary>
        ///// Gets or sets the critical header parameter.
        ///// </summary>
        //public void AddCrit(string[] values)
        //    => Header.Add(HeaderParameters.CritUtf8, values);

        /// <summary>
        /// Encodes the current <see cref="JwtDescriptor"/> into it <see cref="string"/> representation.
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public abstract void Encode(EncodingContext context);

        /// <summary>
        /// Validates the current <see cref="JwtDescriptor"/>.
        /// </summary>
        public virtual void Validate()
        {
        }

        /// <summary>
        /// Validates the presence and the type of a required header.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="type"></param>
        protected void CheckRequiredHeader(string utf8Name, JsonValueKind type)
        {
            if (!Header.TryGetValue(utf8Name, out var tokenType))
            {
                ThrowHelper.ThrowJwtDescriptorException_HeaderIsRequired(utf8Name);
            }

            if (tokenType.Type != type)
            {
                ThrowHelper.ThrowJwtDescriptorException_HeaderMustBeOfType(utf8Name, type);
            }
        }

        /// <summary>
        /// Validates the presence and the type of a required header.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="types"></param>
        protected void CheckRequiredHeader(string utf8Name, JsonValueKind[] types)
        {
            if (!Header.TryGetValue(utf8Name, out var tokenType))
            {
                ThrowHelper.ThrowJwtDescriptorException_HeaderIsRequired(utf8Name);
            }

            for (int i = 0; i < types.Length; i++)
            {
                if (tokenType.Type == types[i])
                {
                    return;
                }
            }

            ThrowHelper.ThrowJwtDescriptorException_HeaderMustBeOfType(utf8Name, types);
        }
    }

    public sealed class JwtHeaderX : IEnumerable
    {
        private readonly MemberStore _header = new MemberStore();

        internal void CopyTo(JwtHeaderX destination)
        {
            _header.CopyTo(destination._header);
        }

        public void Add(string propertyName, string value)
        {
            _header.TryAdd(new JwtMemberX(propertyName, value));
        }

        //public void Add(ReadOnlySpan<byte> propertyName, string? value)
        //{
        //    _header.Add(propertyName, value);
        //}

        //public void Add(string propertyName, ReadOnlySpan<byte> value)
        //{
        //    _header.TryAdd(propertyName, new JwtValueX(value));
        //}

        //public void Add(ReadOnlySpan<byte> propertyName, ReadOnlySpan<byte> value)
        //{
        //    _header.Add(propertyName, value);
        //}

        public void Add(string propertyName, long value)
        {
            _header.TryAdd(new JwtMemberX(propertyName, value));
        }

        //public void Add(ReadOnlySpan<byte> propertyName, long value)
        //{
        //    _header.Add(propertyName, value);
        //}

        public void Add(string propertyName, object[] value)
        {
            _header.TryAdd(new JwtMemberX(propertyName, value));
        }

        //public void Add<T>(ReadOnlySpan<byte> propertyName, T[] value, JsonSerializerOptions? options = default)
        //{
        //    _header.Add(propertyName, value, options);
        //}

        public void Add(string propertyName, string?[] values)
        {
            _header.TryAdd(new JwtMemberX(propertyName, values));
        }

        //public void Add(ReadOnlySpan<byte> propertyName, string?[] values)
        //{
        //    _header.Add(propertyName, values);
        //}

        //public void Add<T>(string propertyName, T value)
        //    where T : class
        //{
        //    _header.TryAdd(propertyName, new JwtValueX(value));
        //}
        public void Add(string propertyName, object value)
        {
            _header.TryAdd(new JwtMemberX(propertyName, value));
        }
        internal void Add(JwtMemberX value)
        {
            _header.TryAdd(value);
        }

        //public void Add<T>(ReadOnlySpan<byte> propertyName, T value, JsonSerializerOptions? options = default)
        //    where T : class
        //{
        //    _header.Add(propertyName, value, options);
        //}

        public IEnumerator GetEnumerator()
        {
            throw new NotImplementedException();
        }

        //internal void Flush()
        //{
        //    _header.Flush();
        ////}

        //internal bool TryGetTokenType(ReadOnlySpan<byte> utf8Name, out JsonTokenType tokenType)
        //    => _header.TryGetTokenType(utf8Name, out tokenType);

        //internal bool TryGetTokenType(ReadOnlySpan<char> utf8Name, out JsonTokenType tokenType)
        //    => _header.TryGetTokenType(utf8Name, out tokenType);
        //internal bool TryGetTokenType(string name, out JsonTokenType tokenType)
        //    => _header.TryGetTokenType(name, out tokenType);

        internal bool TryGetValue(string utf8Name, out JwtMemberX value)
        {
            return _header.TryGetValue(utf8Name, out value);
        }

        internal void WriteObjectTo(Utf8JsonWriter writer)
        {
            _header.WriteTo(writer);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal readonly struct JwtObjectRow
    {
        internal const int Size = 12;
        private readonly int _location;
        private readonly int _propertyLength;
        private readonly int _endPosition;

        /// <summary>
        /// Index into the payload
        /// </summary>
        internal int StartPosition => _location & 0x0FFFFFFF;

        internal JsonTokenType TokenType => (JsonTokenType)(unchecked((uint)_location) >> 28);

        public int Length => _propertyLength;
        public int EndPosition => _endPosition;

        internal JwtObjectRow(JsonTokenType jsonTokenType, int location, int propertyLength, int endPosition)
        {
            Debug.Assert(location >= 0);
            Debug.Assert(location < 1 << 28);

            _location = location | ((int)jsonTokenType << 28);
            _propertyLength = propertyLength;
            _endPosition = endPosition;
        }
    }

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

    [DebuggerDisplay("{DebuggerDisplay(),nq}")]
    public sealed class JwtObjectX : IEnumerable, IDisposable
    {
        private readonly PooledByteBufferWriter _bufferWriter;
        private readonly Utf8JsonWriter _writer;
        private readonly bool _disposable;
        private JwtObjectMetadataDb _database;
        private int _lastPosition;

        public JwtObjectX(bool disposable = true)
        {
            _bufferWriter = new PooledByteBufferWriter();
            _writer = new Utf8JsonWriter(_bufferWriter, Constants.NoJsonValidation);
            _database = new JwtObjectMetadataDb(64);
            _disposable = disposable;
            _writer.WriteStartObject();
        }

        internal int Length => _bufferWriter.WrittenCount;
        internal ReadOnlySpan<byte> Span => _bufferWriter.WrittenSpan;

        private int GetCurrentPosition()
            => _writer.BytesPending + (int)_writer.BytesCommitted;

        public void Flush()
        {
            if (_writer.BytesPending != 0)
            {
                _writer.WriteEndObject();
                _writer.Flush();
            }
        }

        public void Add(string propertyName, string? value)
        {
            int position = _lastPosition + 2;
            _writer.WriteString(propertyName, value);
            int length = _bufferWriter.Buffer.AsSpan(position).IndexOf(JsonConstants.Quote);
            Debug.Assert(length > 0);
            _lastPosition = GetCurrentPosition();
            _database.Append(JsonTokenType.String, position, length, _lastPosition);
        }

        public void Add(ReadOnlySpan<byte> propertyName, string? value)
        {
            int position = _lastPosition + 2;
            _writer.WriteString(propertyName, value);
            int propertyLength = _bufferWriter.Buffer.AsSpan(position).IndexOf(JsonConstants.Quote);
            Debug.Assert(propertyLength > 0);
            _lastPosition = GetCurrentPosition();
            _database.Append(JsonTokenType.String, position, propertyLength, _lastPosition);
        }

        public void Add(string propertyName, ReadOnlySpan<byte> value)
        {
            int position = _lastPosition + 2;
            _writer.WriteString(propertyName, value);
            int length = _bufferWriter.Buffer.AsSpan(position).IndexOf(JsonConstants.Quote);
            Debug.Assert(length > 0);
            _lastPosition = GetCurrentPosition();
            _database.Append(JsonTokenType.String, position, length, _lastPosition);
        }

        public void Add(ReadOnlySpan<byte> propertyName, ReadOnlySpan<byte> value)
        {
            int position = _lastPosition + 2;
            _writer.WriteString(propertyName, value);
            int length = _bufferWriter.Buffer.AsSpan(position).IndexOf(JsonConstants.Quote);
            Debug.Assert(length > 0);
            _lastPosition = GetCurrentPosition();
            _database.Append(JsonTokenType.String, position, length, _lastPosition);
        }

        public void Add(string propertyName, long value)
        {
            int position = _lastPosition + 2;
            _writer.WriteNumber(propertyName, value);
            int length = _bufferWriter.Buffer.AsSpan(position).IndexOf(JsonConstants.Quote);
            Debug.Assert(length > 0);
            _lastPosition = GetCurrentPosition();
            _database.Append(JsonTokenType.Number, position, length, _lastPosition);
        }

        public void Add(ReadOnlySpan<byte> propertyName, long value)
        {
            int position = _lastPosition + 2;
            _writer.WriteNumber(propertyName, value);
            int length = _bufferWriter.Buffer.AsSpan(position).IndexOf(JsonConstants.Quote);
            Debug.Assert(length > 0);
            _lastPosition = GetCurrentPosition();
            _database.Append(JsonTokenType.Number, position, length, _lastPosition);
        }

        public void Add<T>(string propertyName, T[] values, JsonSerializerOptions? options = default)
        {
            int position = _lastPosition + 2;
            _writer.WriteStartArray(propertyName);
            int length = _bufferWriter.Buffer.AsSpan(position).IndexOf(JsonConstants.Quote);
            Debug.Assert(length > 0);
            for (int i = 0; i < values.Length; i++)
            {
                JsonSerializer.Serialize(_writer, values[i], options);
            }

            _writer.WriteEndArray();
            _lastPosition = GetCurrentPosition();
            _database.Append(JsonTokenType.StartArray, position, length, _lastPosition);
        }

        public void Add<T>(ReadOnlySpan<byte> propertyName, T[] values, JsonSerializerOptions? options = default)
        {
            int position = _lastPosition + 2;
            _writer.WriteStartArray(propertyName);
            int length = _bufferWriter.Buffer.AsSpan(position).IndexOf(JsonConstants.Quote);
            Debug.Assert(length > 0);
            for (int i = 0; i < values.Length; i++)
            {
                JsonSerializer.Serialize(_writer, values[i], options);
            }

            _writer.WriteEndArray();
            _lastPosition = GetCurrentPosition();
            _database.Append(JsonTokenType.StartArray, position, length, _lastPosition);
        }

        public void Add(string propertyName, string?[] values)
        {
            int position = _lastPosition + 2;
            _writer.WriteStartArray(propertyName);
            int length = _bufferWriter.Buffer.AsSpan(position).IndexOf(JsonConstants.Quote);
            Debug.Assert(length > 0);
            for (int i = 0; i < values.Length; i++)
            {
                _writer.WriteStringValue(values[i]);
            }

            _writer.WriteEndArray();
            _lastPosition = GetCurrentPosition();
            _database.Append(JsonTokenType.StartArray, position, length, _lastPosition);
        }

        public void Add(ReadOnlySpan<byte> propertyName, string?[] values)
        {
            int position = _lastPosition + 2;
            _writer.WriteStartArray(propertyName);
            int length = _bufferWriter.Buffer.AsSpan(position).IndexOf(JsonConstants.Quote);
            Debug.Assert(length > 0);
            for (int i = 0; i < values.Length; i++)
            {
                _writer.WriteStringValue(values[i]);
            }

            _writer.WriteEndArray();
            _lastPosition = GetCurrentPosition();
            _database.Append(JsonTokenType.StartArray, position, length, _lastPosition);
        }

        public void Add<T>(string propertyName, T value, JsonSerializerOptions? options = default)
            where T : class
        {
            int position = _lastPosition + 2;
            _writer.WritePropertyName(propertyName);
            int length = _bufferWriter.Buffer.AsSpan(position).IndexOf(JsonConstants.Quote);
            Debug.Assert(length > 0);
            JsonSerializer.Serialize(_writer, value, options);
            _lastPosition = GetCurrentPosition();
            _database.Append(JsonTokenType.StartObject, position, length, _lastPosition);
        }

        public void Add<T>(ReadOnlySpan<byte> propertyName, T value, JsonSerializerOptions? options = default)
            where T : class
        {
            int position = _lastPosition + 2;
            _writer.WritePropertyName(propertyName);
            int length = _bufferWriter.Buffer.AsSpan(position).IndexOf(JsonConstants.Quote);
            Debug.Assert(length > 0);
            JsonSerializer.Serialize(_writer, value, options);
            _lastPosition = GetCurrentPosition();
            _database.Append(JsonTokenType.StartObject, position, length, _lastPosition);
        }

        public void Dispose()
        {
            if (_disposable)
            {
                _database.Dispose();
                _writer.Dispose();
                _bufferWriter.Dispose();
            }
        }

        public IEnumerator GetEnumerator()
        {
            throw new NotImplementedException();
        }

        public string DebuggerDisplay()
        {
            return Utf8.GetString(_bufferWriter.WrittenSpan);
        }

        internal bool TryGetTokenType(ReadOnlySpan<byte> propertyName, out JsonTokenType value)
        {
            ReadOnlySpan<byte> documentSpan = _bufferWriter.WrittenSpan;
            Span<byte> utf8UnescapedStack = stackalloc byte[JsonConstants.StackallocThreshold];

            // Move to the row before the EndObject
            int index = 0;
            int endIndex = _database.Length;

            while (index < endIndex)
            {
                JwtObjectRow row = _database.Get(index);
                ReadOnlySpan<byte> currentPropertyName = documentSpan.Slice(row.StartPosition, row.Length);

                if (currentPropertyName.SequenceEqual(propertyName))
                {
                    // If the property name is a match, the answer is the next element.
                    value = row.TokenType;
                    return true;
                }

                // Move to the previous value
                index += JwtObjectRow.Size;
            }

            value = default;
            return false;
        }

        internal bool TryGetTokenType(string propertyName, out JsonTokenType value)
            => TryGetTokenType(propertyName.AsSpan(), out value);

        internal bool TryGetTokenType(ReadOnlySpan<char> propertyName, out JsonTokenType value)
        {
            int maxBytes = Utf8.GetMaxByteCount(propertyName.Length);
            int endIndex = _database.Length;

            if (maxBytes < JsonConstants.StackallocThreshold)
            {
                Span<byte> utf8Name = stackalloc byte[JsonConstants.StackallocThreshold];
                int len = JsonReaderHelper.GetUtf8FromText(propertyName, utf8Name);
                utf8Name = utf8Name.Slice(0, len);

                return TryGetTokenType(utf8Name, out value);
            }

            JwtObjectRow row;
            int minBytes = propertyName.Length;
            for (int candidateIndex = 0; candidateIndex <= endIndex; candidateIndex += JwtObjectRow.Size)
            {
                row = _database.Get(candidateIndex);
                if (row.Length >= minBytes)
                {
                    byte[] tmpUtf8 = ArrayPool<byte>.Shared.Rent(maxBytes);
                    Span<byte> utf8Name = default;

                    try
                    {
                        int len = JsonReaderHelper.GetUtf8FromText(propertyName, tmpUtf8);
                        utf8Name = tmpUtf8.AsSpan(0, len);

                        return TryGetTokenType(utf8Name, out value);
                    }
                    finally
                    {
                        ArrayPool<byte>.Shared.Return(tmpUtf8);
                    }
                }
            }

            value = default;
            return false;
        }
        public bool TryGetValue(ReadOnlySpan<byte> propertyName, out ReadOnlySpan<byte> value)
        {
            ReadOnlySpan<byte> documentSpan = _bufferWriter.WrittenSpan;
            Span<byte> utf8UnescapedStack = stackalloc byte[JsonConstants.StackallocThreshold];

            // Move to the row before the EndObject
            int index = 0;
            int endIndex = _database.Length;

            while (index < endIndex)
            {
                JwtObjectRow row = _database.Get(index);
                ReadOnlySpan<byte> currentPropertyName = documentSpan.Slice(row.StartPosition, row.Length);

                if (currentPropertyName.SequenceEqual(propertyName))
                {
                    // If the property name is a match, the answer is the next element.
                    value = documentSpan.Slice(row.StartPosition + row.Length + 3, row.EndPosition - (row.StartPosition + row.Length + 4));
                    return true;
                }

                // Move to the previous value
                index += JwtObjectRow.Size;
            }

            value = default;
            return false;
        }
    }

    /// <summary>
    ///   Represents the structure of a JWT value in a lightweight, read-only form.
    /// </summary>
    /// <remarks>
    ///   This class utilizes resources from pooled memory to minimize the garbage collector (GC)
    ///   impact in high-usage scenarios. Failure to properly Dispose this object will result in
    ///   the memory not being returned to the pool.
    /// </remarks>
    internal sealed class JwtDocument : IDisposable
    {
        private ReadOnlyMemory<byte> _utf8Json;
        private MetadataDb _parsedData;
        private byte[]? _extraRentedBytes;
        private readonly JwtElement _root;
        private readonly bool _isDisposable;
        private readonly List<IDisposable> _disposableRegistry;

        /// <summary>
        /// The <see cref="JwtElement"/> representing the value of the document.
        /// </summary>
        public JwtElement RootElement => _root;

        /// <summary>
        /// Gets the raw binary value of the <see cref="JwtDocument"/>.
        /// </summary>
        public ReadOnlyMemory<byte> RawValue => _utf8Json;

        internal bool IsDisposable => _isDisposable;

        internal JwtDocument(ReadOnlyMemory<byte> utf8Json, MetadataDb parsedData, byte[]? extraRentedBytes, bool isDisposable = true)
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
            _disposableRegistry = new List<IDisposable>(0);
        }

        ///// <summary>
        ///// Gets 
        ///// </summary>
        ///// <param name="propertyName"></param>
        ///// <returns></returns>
        //public JwtElement this[string propertyName]
        //{
        //    get
        //    {
        //        if (TryGetProperty(propertyName, out var value))
        //        {
        //            return value;
        //        }

        //        throw new KeyNotFoundException();
        //    }
        //}

        //public JwtElement this[ReadOnlySpan<byte> propertyName]
        //{
        //    get
        //    {
        //        if (TryGetProperty(propertyName, out var value))
        //        {
        //            return value;
        //        }

        //        throw new KeyNotFoundException();
        //    }
        //}

        internal bool TryGetNamedPropertyValue(ReadOnlySpan<char> propertyName, out JwtElement value)
        {
            CheckNotDisposed();

            DbRow row;

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
            for (int candidateIndex = 0; candidateIndex <= endIndex; candidateIndex += DbRow.Size * 2)
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
            CheckNotDisposed();

            int endIndex = _parsedData.Length;// checked(row.NumberOfRows * DbRow.Size + index);

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
                DbRow row = _parsedData.Get(index);
                Debug.Assert(row.TokenType == JsonTokenType.PropertyName);

                ReadOnlySpan<byte> currentPropertyName = documentSpan.Slice(row.Location, row.Length);

                if (row.HasComplexChildren)
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
                                    value = new JwtElement(this, index + DbRow.Size);
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
                    value = new JwtElement(this, index + DbRow.Size);
                    return true;
                }

                // Move to the previous value
                index += DbRow.Size * 2;
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
        {
            CheckNotDisposed();

            return _parsedData.GetJsonTokenType(index);
        }

        private void CheckExpectedType(JsonTokenType expected, JsonTokenType actual)
        {
            if (expected != actual)
            {
                //throw ThrowHelper.GetJsonElementWrongTypeException(expected, actual);
                throw new InvalidOperationException();
            }
        }

        private void CheckNotDisposed()
        {
            if (_utf8Json.IsEmpty)
            {
                ThrowHelper.ThrowObjectDisposedException(typeof(JwtDocument));
            }
        }

        internal int GetEndIndex(int index, bool includeEndElement)
        {
            CheckNotDisposed();

            DbRow row = _parsedData.Get(index);

            if (row.IsSimpleValue)
            {
                return index + DbRow.Size;
            }

            int endIndex = index + DbRow.Size * row.NumberOfRows;

            if (includeEndElement)
            {
                endIndex += DbRow.Size;
            }

            return endIndex;
        }

        private ReadOnlyMemory<byte> GetRawValue(int index, bool includeQuotes)
        {
            CheckNotDisposed();

            DbRow row = _parsedData.Get(index);

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
            CheckNotDisposed();

            // The property name is stored one row before the value
            DbRow row = _parsedData.Get(valueIndex - DbRow.Size);
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
            CheckNotDisposed();

            DbRow row = _parsedData.Get(index);

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
            CheckNotDisposed();
            DbRow row = _parsedData.Get(index);

            ReadOnlySpan<byte> data = _utf8Json.Span;
            ReadOnlySpan<byte> segment = data.Slice(row.Location, row.Length);
            return JsonSerializer.Deserialize<TValue>(segment, options);
        }

        internal string?[]? GetStringArray(int index)
        {
            CheckNotDisposed();

            DbRow row = _parsedData.Get(index);

            JsonTokenType tokenType = row.TokenType;

            if (tokenType == JsonTokenType.Null)
            {
                return null;
            }

            CheckExpectedType(JsonTokenType.StartArray, tokenType);

            ReadOnlySpan<byte> data = _utf8Json.Span;
            ReadOnlySpan<byte> segment = data.Slice(row.Location, row.Length);
            string?[] array = new string[row.NumberOfRows];
            var reader = new Utf8JsonReader(segment);
            reader.Read();
            for (int i = 0; i < row.NumberOfRows; i++)
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
            CheckNotDisposed();

            int matchIndex = isPropertyName ? index - DbRow.Size : index;

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
            CheckNotDisposed();

            int matchIndex = isPropertyName ? index - DbRow.Size : index;

            DbRow row = _parsedData.Get(matchIndex);

            CheckExpectedType(
                isPropertyName ? JsonTokenType.PropertyName : JsonTokenType.String,
                row.TokenType);

            ReadOnlySpan<byte> data = _utf8Json.Span;
            ReadOnlySpan<byte> segment = data.Slice(row.Location, row.Length);

            if (otherUtf8Text.Length > segment.Length || (!shouldUnescape && otherUtf8Text.Length != segment.Length))
            {
                return false;
            }

            if (row.HasComplexChildren && shouldUnescape)
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
        {
            // The property name is one row before the property value
            return GetString(index - DbRow.Size, JsonTokenType.PropertyName)!;
        }

        internal bool TryGetValue(int index, out long value)
        {
            CheckNotDisposed();

            DbRow row = _parsedData.Get(index);

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
            CheckNotDisposed();

            DbRow row = _parsedData.Get(index);

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
            CheckNotDisposed();

            DbRow row = _parsedData.Get(index);

            //   CheckExpectedType(JsonTokenType.StartObject, row.TokenType);

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
            return GetRawValue(index, includeQuotes: true);
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
            MetadataDb newDb = _parsedData.CopySegment(index, endIndex);
            ReadOnlyMemory<byte> segmentCopy = GetRawValue(index, includeQuotes: true).ToArray();

            JwtDocument newDocument = new JwtDocument(segmentCopy, newDb, extraRentedBytes: null, isDisposable: false);

            return newDocument._root;
        }

        internal JwtDocument Clone()
        {
            MetadataDb newDb = _parsedData.Clone();
            ReadOnlyMemory<byte> segmentCopy = _utf8Json.ToArray();
            JwtDocument newDocument = new JwtDocument(segmentCopy, newDb, extraRentedBytes: null, isDisposable: false);

            return newDocument;
        }

        internal int GetArrayLength(int index)
        {
            CheckNotDisposed();

            DbRow row = _parsedData.Get(index);

            CheckExpectedType(JsonTokenType.StartArray, row.TokenType);

            return row.Length;
        }


        internal int GetMemberCount(int index)
        {
            CheckNotDisposed();

            DbRow row = _parsedData.Get(index);

            CheckExpectedType(JsonTokenType.StartObject, row.TokenType);

            return row.NumberOfRows;
        }

        internal JwtElement GetArrayIndexElement(int currentIndex, int arrayIndex)
        {
            CheckNotDisposed();

            DbRow row = _parsedData.Get(currentIndex);

            CheckExpectedType(JsonTokenType.StartArray, row.TokenType);

            int arrayLength = row.Length;

            if ((uint)arrayIndex >= (uint)arrayLength)
            {
                throw new IndexOutOfRangeException();
            }

            if (!row.HasComplexChildren)
            {
                // Since we wouldn't be here without having completed the document parse, and we
                // already vetted the index against the length, this new index will always be
                // within the table.
                return new JwtElement(this, currentIndex + ((arrayIndex + 1) * DbRow.Size));
            }

            int elementCount = 0;
            int objectOffset = currentIndex + DbRow.Size;

            for (; objectOffset < _parsedData.Length; objectOffset += DbRow.Size)
            {
                if (arrayIndex == elementCount)
                {
                    return new JwtElement(this, objectOffset);
                }

                row = _parsedData.Get(objectOffset);

                if (!row.IsSimpleValue)
                {
                    objectOffset += DbRow.Size * row.NumberOfRows;
                }

                elementCount++;
            }

            Debug.Fail(
                $"Ran out of database searching for array index {arrayIndex} from {currentIndex} when length was {arrayLength}");
            throw new IndexOutOfRangeException();
        }


        /// <summary>
        /// Determines whether the <see cref="JwtPayload"/> contains the specified key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public bool ContainsKey(ReadOnlySpan<byte> key)
        {
            return _root.TryGetProperty(key, out _);
        }

        /// <summary>
        /// Gets the value associated with the specified key.
        /// </summary>
        public bool TryGetProperty(ReadOnlySpan<byte> key, [NotNullWhen(true)] out JwtElement value)
        {
            return _root.TryGetProperty(key, out value);
        }

        /// <summary>
        /// Gets the value associated with the specified key.
        /// </summary>
        public bool TryGetProperty(string key, out JwtElement value)
        {
            return _root.TryGetProperty(key, out value);
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
    }
}