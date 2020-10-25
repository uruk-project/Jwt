using System;
using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Threading;
using JsonWebToken.Internal;

namespace JsonWebToken
{
    /// <summary>
    ///   Represents the structure of a JWT value in a read-only form.
    /// </summary>
    /// <remarks>
    ///   This class utilizes resources from pooled memory to minimize the garbage collector (GC)
    ///   impact in high-usage scenarios. Failure to properly Dispose this object will result in
    ///   the memory not being returned to the pool, which will cause an increase in GC impact across
    ///   various parts of the framework.
    /// </remarks>
    public partial class Jwt : IDisposable
    {
        private ReadOnlyMemory<byte> _rawValue;
        private byte[]? _rented;
        private readonly JwtHeaderDocument _header;
        private readonly JwtPayloadDocument? _payload;
        private readonly Jwt? _nested;
        private readonly TokenValidationError? _error;

        internal Jwt(JwtHeaderDocument header, ReadOnlyMemory<byte> rawValue, byte[] rented)
        {
            _header = header;
            _rawValue = rawValue;
            _rented = rented;
        }

        internal Jwt(TokenValidationError error)
        {
            _error = error;
        }

        internal Jwt(JwtHeaderDocument header, Jwt nested, byte[] rented)
        {
            _header = header;
            _payload = nested.Payload;
            _nested = nested;
            _rented = rented;
        }

        internal Jwt(JwtHeaderDocument header, JwtPayloadDocument payload, byte[] rented)
        {
            _header = header;
            _payload = payload;
            _rented = rented;
        }

        internal Jwt(JwtHeaderDocument header, JwtPayloadDocument payload, TokenValidationError error)
        {
            _header = header;
            _payload = payload;
            _error = error;
        }

        internal Jwt(JwtHeaderDocument header, Jwt nested, TokenValidationError error, byte[] rented)
        {
            _header = header;
            _payload = nested.Payload;
            _nested = nested;
            _error = error;
            _rented = rented;
        }

        public TokenValidationError? Error => _error;
        public JwtHeaderDocument Header => _header;
        public JwtPayloadDocument? Payload => _payload;
        public Jwt? Nested => _nested;
        public ReadOnlyMemory<byte> RawValue => _rawValue;

        public static bool TryParse(ReadOnlySpan<byte> utf8Token, TokenValidationPolicy policy, out Jwt document)
        {
            if (policy is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.policy);
            }

            TokenValidationError? error;
            if (utf8Token.IsEmpty)
            {
                error = TokenValidationError.MalformedToken();
                goto TokenAnalyzed;
            }

            if (utf8Token.Length > policy.MaximumTokenSizeInBytes)
            {
                error = TokenValidationError.MalformedToken();
                goto TokenAnalyzed;
            }

            Span<TokenSegment> segments = stackalloc TokenSegment[Constants.JweSegmentCount];
            ref TokenSegment segmentsRef = ref MemoryMarshal.GetReference(segments);
            int segmentCount = Tokenizer.Tokenize(utf8Token, ref segmentsRef);
            if (segmentCount < Constants.JwsSegmentCount)
            {
                error = TokenValidationError.MalformedToken();
                goto TokenAnalyzed;
            }

            var headerSegment = segmentsRef;
            if (headerSegment.IsEmpty)
            {
                error = TokenValidationError.MalformedToken();
                goto TokenAnalyzed;
            }

            JwtHeaderDocument? header;
            var rawHeader = utf8Token.Slice(0, headerSegment.Length);
            int headerJsonDecodedLength = Base64Url.GetArraySizeRequiredToDecode(rawHeader.Length);
            int payloadjsonDecodedLength;
            int jsonBufferLength;

            // For JWS, the payload is in position '1' (= 3 - 2)
            // For JWE, the payload is in position '3' (= 5 - 2)
            int segmentPayloadOffset = segmentCount - 2;
            payloadjsonDecodedLength = Base64Url.GetArraySizeRequiredToDecode(Unsafe.Add(ref segmentsRef, segmentPayloadOffset).Length);
            jsonBufferLength = headerJsonDecodedLength + payloadjsonDecodedLength;

            byte[] jsonBuffer = ArrayPool<byte>.Shared.Rent(jsonBufferLength);
            bool wellFormedJwt = false;
            try
            {
                bool validHeader;
                if (policy.HeaderCache.Enabled)
                {
                    IJwtHeader? tmp;
                    if (!policy.HeaderCache.TryGetHeader(rawHeader, out tmp))
                    {
                        int decodedHeaderLength = Base64Url.Decode(rawHeader, new Span<byte>(jsonBuffer, 0, jsonBuffer.Length));
                        Debug.Assert(headerJsonDecodedLength == decodedHeaderLength);
                        if (validHeader = TryReadHeader(new ReadOnlyMemory<byte>(jsonBuffer, 0, decodedHeaderLength), policy, out header, out error))
                        {
                            policy.HeaderCache.AddHeader(rawHeader, header);
                        }
                    }
                    else
                    {
                        header = (JwtHeaderDocument)tmp;
                        validHeader = policy.TryValidateHeader(header, out error);
                    }
                }
                else
                {
                    int decodedHeaderLength = Base64Url.Decode(rawHeader, jsonBuffer);
                    validHeader = TryReadHeader(new ReadOnlyMemory<byte>(jsonBuffer, 0, decodedHeaderLength), policy, out header, out error);
                }

                if (validHeader)
                {
                    wellFormedJwt = segmentCount switch
                    {
                        Constants.JwsSegmentCount => TryReadJws(utf8Token, jsonBuffer, headerJsonDecodedLength, payloadjsonDecodedLength, policy, ref segmentsRef, header, out document),
                        Constants.JweSegmentCount => TryReadJwe(utf8Token, jsonBuffer, headerJsonDecodedLength, payloadjsonDecodedLength, policy, rawHeader, ref segmentsRef, header, out document),
                        _ => InvalidDocument(TokenValidationError.MalformedToken($"JWT must have 3 or 5 segments. The current token has {segmentCount} segments."), out document),
                    };
                    return wellFormedJwt;
                }
            }
            catch (FormatException formatException)
            {
                error = TokenValidationError.MalformedToken(formatException);
            }
            catch (JsonException readerException)
            {
                error = TokenValidationError.MalformedToken(readerException);
            }
            catch (InvalidOperationException invalidOperationException) when (invalidOperationException.InnerException is DecoderFallbackException)
            {
                error = TokenValidationError.MalformedToken(invalidOperationException);
            }
            finally
            {
                if (!wellFormedJwt)
                {
                    ArrayPool<byte>.Shared.Return(jsonBuffer);
                }
            }

        TokenAnalyzed:
            return InvalidDocument(error, out document);

            static bool InvalidDocument(TokenValidationError error, out Jwt document)
            {
                document = new Jwt(error);
                return false;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static bool TryReadHeader(ReadOnlyMemory<byte> utf8Header, TokenValidationPolicy policy, [NotNullWhen(true)] out JwtHeaderDocument? header, [NotNullWhen(false)] out TokenValidationError? error)
        {
            if (JwtHeaderDocument.TryParse(utf8Header, policy, out header, out error))
            {
                return policy.TryValidateHeader(header, out error);
            }

            return false;
        }

        private static bool TryReadJws(
            ReadOnlySpan<byte> utf8Buffer,
            byte[] jsonBuffer,
            int jsonBufferOffset,
            int jsonBufferLength,
            TokenValidationPolicy policy,
            ref TokenSegment segments,
            JwtHeaderDocument header,
            out Jwt jwt)
        {
            TokenSegment headerSegment = segments;
            TokenSegment payloadSegment = Unsafe.Add(ref segments, 1);
            TokenSegment signatureSegment = Unsafe.Add(ref segments, 2);
            var rawPayload = utf8Buffer.Slice(payloadSegment.Start, payloadSegment.Length);
            var result = policy.TryValidateSignature(
                header,
                utf8Buffer.Slice(headerSegment.Start, headerSegment.Length + payloadSegment.Length + 1),
                utf8Buffer.Slice(signatureSegment.Start, signatureSegment.Length));
            if (!result.Succedeed)
            {
                jwt = new Jwt(TokenValidationError.SignatureValidationFailed(result));
                goto Error;
            }

            try
            {
                int bytesWritten = Base64Url.Decode(rawPayload, new Span<byte>(jsonBuffer, jsonBufferOffset, jsonBufferLength));
                Debug.Assert(bytesWritten == jsonBufferLength);
                if (TryReadPayload(
                    new ReadOnlyMemory<byte>(jsonBuffer, jsonBufferOffset, jsonBufferLength),
                    policy,
                    out JwtPayloadDocument? payload,
                    out TokenValidationError? error))
                {
                    if (policy.TryValidateJwt(header, payload, out error))
                    {
                        jwt = new Jwt(header, payload, jsonBuffer);
                        return true;
                    }
                    else
                    {
                        jwt = new Jwt(header, payload, error);
                        goto Error;
                    }
                }
                else
                {
                    jwt = new Jwt(error);
                    goto Error;
                }
            }
            catch (FormatException formatException)
            {
                jwt = new Jwt(TokenValidationError.MalformedToken(formatException));
                goto Error;
            }
            catch (JsonException readerException)
            {
                jwt = new Jwt(TokenValidationError.MalformedToken(readerException));
                goto Error;
            }
            catch (InvalidOperationException invalidOperationException) when (invalidOperationException.InnerException is DecoderFallbackException)
            {
                jwt = new Jwt(TokenValidationError.MalformedToken(invalidOperationException));
                goto Error;
            }

        Error:
            return false;
        }

        private static bool TryReadJwe(
            ReadOnlySpan<byte> utf8Buffer,
            byte[] jsonBuffer,
            int jsonBufferOffset,
            int jsonBufferLength,
            TokenValidationPolicy policy,
            ReadOnlySpan<byte> rawHeader,
            ref TokenSegment segments,
            JwtHeaderDocument header,
            out Jwt document)
        {
            TokenValidationError error;
            TokenSegment encryptionKeySegment = Unsafe.Add(ref segments, 1);
            TokenSegment ivSegment = Unsafe.Add(ref segments, 2);
            TokenSegment ciphertextSegment = Unsafe.Add(ref segments, 3);
            TokenSegment authenticationTagSegment = Unsafe.Add(ref segments, 4);
            if (!header.TryGetHeaderParameter(HeaderParameters.EncUtf8, out var enc))
            {
                error = TokenValidationError.MissingEncryptionAlgorithm();
                goto Error;
            }

            if (!EncryptionAlgorithm.TryParse(enc, out var encryptionAlgorithm))
            {
                // Should be not supported encryption algorithm
                error = TokenValidationError.MissingEncryptionAlgorithm();
                goto Error;
            }

            if (!JwtReaderHelper.TryGetContentEncryptionKeys(header, utf8Buffer.Slice(encryptionKeySegment.Start, encryptionKeySegment.Length), encryptionAlgorithm, policy.DecryptionKeyProviders, out var keys))
            {
                error = TokenValidationError.EncryptionKeyNotFound();
                goto Error;
            }

            var rawInitializationVector = utf8Buffer.Slice(ivSegment.Start, ivSegment.Length);
            var rawCiphertext = utf8Buffer.Slice(ciphertextSegment.Start, ciphertextSegment.Length);
            var rawAuthenticationTag = utf8Buffer.Slice(authenticationTagSegment.Start, authenticationTagSegment.Length);

            Span<byte> decryptedBytes = new Span<byte>(jsonBuffer, jsonBufferOffset, jsonBufferLength);
            if (JwtReaderHelper.TryDecryptToken(keys, rawHeader, rawCiphertext, rawInitializationVector, rawAuthenticationTag, encryptionAlgorithm, decryptedBytes, out SymmetricJwk? decryptionKey, out int bytesWritten))
            {
                decryptedBytes = decryptedBytes.Slice(0, bytesWritten);
            }
            else
            {
                error = TokenValidationError.DecryptionFailed();
                goto Error;
            }

            bool compressed;
            ReadOnlySequence<byte> decompressedBytes = default;
            if (!header.TryGetHeaderParameter(HeaderParameters.ZipUtf8, out var zip))
            {
                compressed = false;
            }
            else
            {
                if (!CompressionAlgorithm.TryParse(zip, out var compressionAlgorithm))
                {
                    error = TokenValidationError.InvalidHeader(HeaderParameters.ZipUtf8);
                    goto Error;
                }

                var compressor = compressionAlgorithm.Compressor;

                //using (var bufferWriter = new PooledByteBufferWriter(decryptedBytes.Length * 3))
                {
                    try
                    {
                        compressed = true;
                        decompressedBytes = compressor.Decompress(decryptedBytes);
                    }
                    catch (Exception e)
                    {
                        error = TokenValidationError.DecompressionFailed(e);
                        goto Error;
                    }
                }
            }

            Jwt jwe;
            if (policy.IgnoreNestedToken)
            {
                ReadOnlyMemory<byte> rawValue = compressed
                    ? decompressedBytes.IsSingleSegment
                        ? decompressedBytes.First
                        : decompressedBytes.ToArray()
                    : new ReadOnlyMemory<byte>(jsonBuffer, jsonBufferOffset, bytesWritten);
                jwe = new Jwt(header, rawValue, jsonBuffer);
            }
            else
            {
                bool decrypted = compressed
                    ? TryParse(decompressedBytes, policy, out var nestedDocument)
                    : TryParse(decryptedBytes, policy, out nestedDocument);
                if (decrypted)
                {
                    jwe = new Jwt(header, nestedDocument, jsonBuffer);
                }
                else
                {
                    if (nestedDocument.Error!.Status == TokenValidationStatus.MalformedToken)
                    {
                        // The decrypted payload is not a nested JWT
                        var rawValue = compressed
                           ? decompressedBytes.IsSingleSegment
                               ? decompressedBytes.First
                               : decompressedBytes.ToArray()
                           : new ReadOnlyMemory<byte>(jsonBuffer, jsonBufferOffset, bytesWritten);
                        jwe = new Jwt(header, rawValue, jsonBuffer);
                    }
                    else
                    {
                        jwe = new Jwt(header, nestedDocument, nestedDocument.Error, jsonBuffer);
                    }
                }
            }

            document = jwe;
            return true;

        Error:
            document = new Jwt(error);
            ArrayPool<byte>.Shared.Return(jsonBuffer);
            return false;
        }

        public static bool TryReadPayload(ReadOnlyMemory<byte> utf8Payload, TokenValidationPolicy policy, [NotNullWhen(true)] out JwtPayloadDocument? payload, [NotNullWhen(false)] out TokenValidationError? error)
        {
            return JwtPayloadDocument.TryParse(utf8Payload, policy, out payload, out error);
        }

        public static bool TryParse(ReadOnlySequence<byte> utf8Token, TokenValidationPolicy policy, out Jwt document)
        {
            if (utf8Token.IsSingleSegment)
            {
                return TryParse(utf8Token.First.Span, policy, out document);
            }

            return TryParse(utf8Token.ToArray(), policy, out document);
        }

        /// <summary>
        /// Reads and validates a JWT encoded as a JWS or JWE in compact serialized format.
        /// </summary>
        /// <param name="token">The JWT encoded as JWE or JWS</param>
        /// <param name="policy">The validation policy.</param>
        /// <param name="document">The parsed <see cref="Jwt"/>.</param>
        public static bool TryParse(string token, TokenValidationPolicy policy, out Jwt document)
        {
            if (token is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.token);
            }

            if (policy is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.policy);
            }

            if (token.Length == 0)
            {
                document = new Jwt(TokenValidationError.MalformedToken());
                return false;
            }

            int length = Utf8.GetMaxByteCount(token.Length);
            if (length > policy.MaximumTokenSizeInBytes)
            {
                document = new Jwt(TokenValidationError.MalformedToken());
                return false;
            }

            byte[]? utf8ArrayToReturnToPool = null;
            var utf8Token = length <= Constants.MaxStackallocBytes
                  ? stackalloc byte[length]
                  : (utf8ArrayToReturnToPool = ArrayPool<byte>.Shared.Rent(length));
            try
            {
                int bytesWritten = Utf8.GetBytes(token, utf8Token);
                return TryParse(utf8Token.Slice(0, bytesWritten), policy, out document);
            }
            finally
            {
                if (utf8ArrayToReturnToPool != null)
                {
                    ArrayPool<byte>.Shared.Return(utf8ArrayToReturnToPool);
                }
            }
        }

        /// <inheritdoc />
        public void Dispose()
        {
            _rawValue = ReadOnlyMemory<byte>.Empty;
            _payload?.Dispose();
            byte[]? rented = Interlocked.Exchange(ref _rented, null);
            if (rented != null)
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }
    }

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
    internal struct MetadataDb : IDisposable
    {
        private const int SizeOrLengthOffset = 4;
        private const int NumberOfRowsOffset = 8;

        internal int Length { get; private set; }
        public int Count { get; private set; }

        private byte[] _data;

        internal MetadataDb(byte[] completeDb)
        {
            _data = completeDb;
            Length = completeDb.Length;
            Count = completeDb.Length / DbRow.Size;
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
            Count = 0;
        }

        internal MetadataDb(MetadataDb source, bool useArrayPools)
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

            Count = Length / DbRow.Size;
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

    [StructLayout(LayoutKind.Sequential)]
    internal readonly struct DbRow
    {
        internal const int Size = 12;

        // Sign bit is currently unassigned
        private readonly int _location;

        // Sign bit is used for "HasComplexChildren" (StartArray)
        private readonly int _lengthUnion;

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
        internal int Length => _lengthUnion & int.MaxValue;

        internal bool IsUnknownSize => _lengthUnion == UnknownSize;

        /// <summary>
        /// String/PropertyName: Unescaping is required.
        /// Array: At least one element is an object/array.
        /// Otherwise; false
        /// </summary>
        internal bool HasComplexChildren => _lengthUnion < 0;

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
            _lengthUnion = sizeOrLength;
            _numberOfRowsAndTypeUnion = (int)jsonTokenType << 28;
        }

        internal bool IsSimpleValue => TokenType >= JsonTokenType.PropertyName;
    }
}