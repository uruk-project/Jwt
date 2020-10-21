using System;
using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
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
    public partial class JwtDocument3 : IDisposable
    {
        private ReadOnlyMemory<byte> _rawValue;
        private byte[]? _rented;
        private readonly JwtHeader _header;
        private readonly JwtPayloadDocument? _payload;
        private readonly JwtDocument3? _nested;
        private readonly TokenValidationError? _error;

        public JwtDocument3(JwtHeader header, ReadOnlyMemory<byte> rawValue, byte[] rented)
        {
            _header = header;
            _rawValue = rawValue;
            _rented = rented;
        }

        public JwtDocument3(TokenValidationError error)
        {
            _error = error;
        }

        public JwtDocument3(JwtHeader header, JwtDocument3 nested, byte[] rented)
        {
            _header = header;
            _payload = nested.Payload;
            _nested = nested;
            _rented = rented;
        }

        public JwtDocument3(JwtHeader header, JwtPayloadDocument payload)
        {
            _header = header;
            _payload = payload;
        }

        public JwtDocument3(JwtHeader header, JwtPayloadDocument payload, TokenValidationError error)
        {
            _header = header;
            _payload = payload;
            _error = error;
        }

        public JwtDocument3(JwtHeader header, JwtDocument3 nested, TokenValidationError error, byte[] rented)
        {
            _header = header;
            _payload = nested.Payload;
            _nested = nested;
            _error = error;
            _rented = rented;
        }

        public TokenValidationError? Error => _error;
        public JwtHeader? Header => _header;
        public JwtPayloadDocument? Payload => _payload;
        public JwtDocument3? Nested => _nested;
        public ReadOnlyMemory<byte> RawValue => _rawValue;

        public static bool TryParse3(ReadOnlySpan<byte> utf8Token, TokenValidationPolicy policy, out JwtDocument3 document)
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

            JwtHeader? header;
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
                        validHeader = TryReadHeader(new ReadOnlySpan<byte>(jsonBuffer, 0, decodedHeaderLength), policy, segmentCount, out header, out error);
                        policy.HeaderCache.AddHeader(rawHeader, header);
                    }
                    else
                    {
                        header = (JwtHeader)tmp;
                        validHeader = policy.TryValidateHeader(header, out error);
                    }
                }
                else
                {
                    int decodedHeaderLength = Base64Url.Decode(rawHeader, jsonBuffer);
                    validHeader = TryReadHeader(new ReadOnlySpan<byte>(jsonBuffer, 0, decodedHeaderLength), policy, segmentCount, out header, out error);
                }

                if (validHeader)
                {
                    return segmentCount switch
                    {
                        Constants.JwsSegmentCount => TryReadJws(utf8Token, jsonBuffer, headerJsonDecodedLength, payloadjsonDecodedLength, policy, ref segmentsRef, header, out document),
                        Constants.JweSegmentCount => TryReadJwe(utf8Token, jsonBuffer, headerJsonDecodedLength, payloadjsonDecodedLength, policy, rawHeader, ref segmentsRef, header, out document),
                        _ => InvalidDocument(TokenValidationError.MalformedToken($"JWT must have 3 or 5 segments. The current token has {segmentCount} segments."), out document),
                    };
                }
            }
            catch (FormatException formatException)
            {
                error = TokenValidationError.MalformedToken(formatException);
                goto TokenAnalyzed;
            }
            catch (JsonException readerException)
            {
                error = TokenValidationError.MalformedToken(readerException);
                goto TokenAnalyzed;
            }
            catch (InvalidOperationException invalidOperationException) when (invalidOperationException.InnerException is DecoderFallbackException)
            {
                error = TokenValidationError.MalformedToken(invalidOperationException);
                goto TokenAnalyzed;
            }

        TokenAnalyzed:
            return InvalidDocument(error, out document);

            static bool InvalidDocument(TokenValidationError error, out JwtDocument3 document)
            {
                document = new JwtDocument3(error);
                return false;
            }
        }

        internal static bool TryReadBase64Header(ReadOnlySpan<byte> utf8Header, TokenValidationPolicy policy, int segmentCount, out JwtHeader header, out TokenValidationError? error)
        {
            int headerJsonDecodedLength = Base64Url.GetArraySizeRequiredToDecode((int)utf8Header.Length);
            var headerBufferToReturnToPool = ArrayPool<byte>.Shared.Rent(headerJsonDecodedLength);
            try
            {
                Base64Url.Decode(utf8Header, headerBufferToReturnToPool);
                return TryReadHeader(new ReadOnlySpan<byte>(headerBufferToReturnToPool, 0, headerJsonDecodedLength), policy, segmentCount, out header, out error);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(headerBufferToReturnToPool);
            }
        }

        internal static bool TryReadHeader(ReadOnlySpan<byte> utf8Header, TokenValidationPolicy policy, int segmentCount, out JwtHeader header, [NotNullWhen(false)] out TokenValidationError? error)
        {
            header = new JwtHeader();
            bool result;
            var reader = new JwtHeaderReader(utf8Header, policy);
            if (reader.ReadFirstBytes())
            {
                while (reader.Read())
                {
                    var name = reader.TokenName;
                    switch (reader.TokenType)
                    {
                        case JsonTokenType.StartObject:
                            header.Inner.Add(name, reader.GetJwtObject());
                            break;
                        case JsonTokenType.StartArray:
                            if (reader.TokenName.Length == 4 && IntegerMarshal.ReadUInt32(reader.TokenName) == (uint)JwtHeaderParameters.Crit)
                            {
                                var crit = reader.GetCriticalHeaders();
                                header.Inner.Add(name, new JwtArray(crit.Item1));
                                header.CriticalHeaderHandlers = crit.Item2;
                                continue;
                            }

                            header.Inner.Add(name, reader.GetJwtArray());
                            break;
                        case JsonTokenType.String:
                            if (reader.TokenName.Length == 3)
                            {
                                switch ((JwtHeaderParameters)IntegerMarshal.ReadUInt24(reader.TokenName))
                                {
                                    case JwtHeaderParameters.Alg:
                                        if (segmentCount == Constants.JwsSegmentCount)
                                        {
                                            header.SignatureAlgorithm = reader.GetSignatureAlgorithm();
                                        }
                                        else if (segmentCount == Constants.JweSegmentCount)
                                        {
                                            header.KeyManagementAlgorithm = reader.GetKeyManagementAlgorithm();
                                        }
                                        continue;
                                    case JwtHeaderParameters.Enc:
                                        header.EncryptionAlgorithm = reader.GetEncryptionAlgorithm();
                                        continue;
                                    case JwtHeaderParameters.Zip:
                                        header.CompressionAlgorithm = reader.GetCompressionAlgorithm();
                                        continue;
                                    case JwtHeaderParameters.Cty:
                                        header.Cty = reader.GetString();
                                        continue;
                                    case JwtHeaderParameters.Typ:
                                        header.Typ = reader.GetString();
                                        continue;
                                    case JwtHeaderParameters.Kid:
                                        header.Kid = reader.GetString();
                                        continue;
                                }
                            }

                            header.Inner.Add(name, reader.GetString()!);
                            break;
                        case JsonTokenType.True:
                            header.Inner.Add(name, true);
                            break;
                        case JsonTokenType.False:
                            header.Inner.Add(name, false);
                            break;
                        case JsonTokenType.Null:
                            header.Inner.Add(name);
                            break;
                        case JsonTokenType.Number:
                            if (reader.TryGetInt64(out long longValue))
                            {
                                header.Inner.Add(name, longValue);
                            }
                            else
                            {
                                header.Inner.Add(name, reader.GetDouble());
                            }
                            break;
                    }
                }

                if (reader.TokenType is JsonTokenType.EndObject)
                {
                    result = reader.TryValidateHeader(header, out error);
                }
                else
                {
                    result = false;
                    error = TokenValidationError.MalformedToken();
                }
            }
            else
            {
                result = false;
                error = TokenValidationError.MalformedToken();
            }

            return result;
        }

        private static bool TryReadJws(
            ReadOnlySpan<byte> utf8Buffer,
            byte[] jsonBuffer,
            int jsonBufferOffset,
            int jsonBufferLength,
            TokenValidationPolicy policy,
            ref TokenSegment segments,
            JwtHeader header,
            out JwtDocument3 jwt)
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
                jwt = new JwtDocument3(TokenValidationError.SignatureValidationFailed(result));
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
                        jwt = new JwtDocument3(header, payload);
                        return true;
                    }
                    else
                    {
                        jwt = new JwtDocument3(header, payload, error);
                        goto Error;
                    }
                }
                else
                {
                    jwt = new JwtDocument3(error);
                    goto Error;
                }
            }
            catch (FormatException formatException)
            {
                jwt = new JwtDocument3(TokenValidationError.MalformedToken(formatException));
                goto Error;
            }
            catch (JsonException readerException)
            {
                jwt = new JwtDocument3(TokenValidationError.MalformedToken(readerException));
                goto Error;
            }
            catch (InvalidOperationException invalidOperationException) when (invalidOperationException.InnerException is DecoderFallbackException)
            {
                jwt = new JwtDocument3(TokenValidationError.MalformedToken(invalidOperationException));
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
            JwtHeader header,
            out JwtDocument3 document)
        {
            TokenValidationError error;
            TokenSegment encryptionKeySegment = Unsafe.Add(ref segments, 1);
            TokenSegment ivSegment = Unsafe.Add(ref segments, 2);
            TokenSegment ciphertextSegment = Unsafe.Add(ref segments, 3);
            TokenSegment authenticationTagSegment = Unsafe.Add(ref segments, 4);
            var enc = header.EncryptionAlgorithm;
            if (enc is null)
            {
                error = TokenValidationError.MissingEncryptionAlgorithm();
                goto Error;
            }

            if (!JwtReaderHelper.TryGetContentEncryptionKeys(header, utf8Buffer.Slice(encryptionKeySegment.Start, encryptionKeySegment.Length), enc, policy.DecryptionKeyProviders, out var keys))
            {
                error = TokenValidationError.EncryptionKeyNotFound();
                goto Error;
            }

            var rawInitializationVector = utf8Buffer.Slice(ivSegment.Start, ivSegment.Length);
            var rawCiphertext = utf8Buffer.Slice(ciphertextSegment.Start, ciphertextSegment.Length);
            var rawAuthenticationTag = utf8Buffer.Slice(authenticationTagSegment.Start, authenticationTagSegment.Length);

            Span<byte> decryptedBytes = new Span<byte>(jsonBuffer, jsonBufferOffset, jsonBufferLength);
            if (JwtReaderHelper.TryDecryptToken(keys, rawHeader, rawCiphertext, rawInitializationVector, rawAuthenticationTag, enc, decryptedBytes, out SymmetricJwk? decryptionKey, out int bytesWritten))
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
            var zip = header.CompressionAlgorithm;
            if (zip is null)
            {
                compressed = false;
            }
            else
            {
                Compressor compressor = zip.Compressor;
                if (compressor is null)
                {
                    error = TokenValidationError.InvalidHeader(HeaderParameters.ZipUtf8);
                    goto Error;
                }

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

            JwtDocument3 jwe;
            if (policy.IgnoreNestedToken)
            {
                ReadOnlyMemory<byte> rawValue = compressed
                    ? decompressedBytes.IsSingleSegment
                        ? decompressedBytes.First
                        : decompressedBytes.ToArray()
                    : new ReadOnlyMemory<byte>(jsonBuffer, jsonBufferOffset, bytesWritten);
                jwe = new JwtDocument3(header, rawValue, jsonBuffer);
            }
            else
            {
                bool decrypted = compressed
                    ? TryParse(decompressedBytes, policy, out var nestedDocument)
                    : TryParse3(decryptedBytes, policy, out nestedDocument);
                if (decrypted)
                {
                    jwe = new JwtDocument3(header, nestedDocument, jsonBuffer);
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
                        jwe = new JwtDocument3(header, rawValue, jsonBuffer);
                    }
                    else
                    {
                        jwe = new JwtDocument3(header, nestedDocument, nestedDocument.Error, jsonBuffer);
                    }
                }
            }

            document = jwe;
            return true;

        Error:
            document = new JwtDocument3(error);
            ArrayPool<byte>.Shared.Return(jsonBuffer);
            return false;
        }

        public static bool TryReadPayload(ReadOnlyMemory<byte> utf8Payload, TokenValidationPolicy policy, [NotNullWhen(true)] out JwtPayloadDocument? payload, [NotNullWhen(false)] out TokenValidationError? error)
        {
            return JwtPayloadDocument.TryParse(utf8Payload, policy, out payload, out error);
        }

        public static bool TryParse(ReadOnlySequence<byte> utf8Token, TokenValidationPolicy policy, out JwtDocument3 document)
        {
            if (utf8Token.IsSingleSegment)
            {
                return TryParse3(utf8Token.First.Span, policy, out document);
            }

            return TryParse3(utf8Token.ToArray(), policy, out document);
        }

        /// <summary>
        /// Reads and validates a JWT encoded as a JWS or JWE in compact serialized format.
        /// </summary>
        /// <param name="token">The JWT encoded as JWE or JWS</param>
        /// <param name="policy">The validation policy.</param>
        /// <param name="document">The parsed <see cref="JwtDocument3"/>.</param>
        public static bool TryParse(string token, TokenValidationPolicy policy, out JwtDocument3 document)
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
                document = new JwtDocument3(TokenValidationError.MalformedToken());
                return false;
            }

            int length = Utf8.GetMaxByteCount(token.Length);
            if (length > policy.MaximumTokenSizeInBytes)
            {
                document = new JwtDocument3(TokenValidationError.MalformedToken());
                return false;
            }

            byte[]? utf8ArrayToReturnToPool = null;
            var utf8Token = length <= Constants.MaxStackallocBytes
                  ? stackalloc byte[length]
                  : (utf8ArrayToReturnToPool = ArrayPool<byte>.Shared.Rent(length));
            try
            {
                int bytesWritten = Utf8.GetBytes(token, utf8Token);
                return TryParse3(utf8Token.Slice(0, bytesWritten), policy, out document);
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

    //    public sealed partial class JwtPayloadDocument
    //    {
    //        private ReadOnlyMemory<byte> _utf8Json;
    //        private MetadataDb _parsedData;
    //        private byte[]? _extraRentedBytes;

    //        private (int, string?) _lastIndexAndString = (-1, null);
    //        internal bool IsDisposable { get; }

    //        /// <summary>
    //        ///   The <see cref="JwtElement"/> representing the value of the document.
    //        /// </summary>
    //        public JwtElement RootElement => new JwtElement(this, 0);

    //        private JwtPayloadDocument(ReadOnlyMemory<byte> utf8Json, MetadataDb parsedData, byte[]? extraRentedBytes,
    //            bool isDisposable = true)
    //        {
    //            Debug.Assert(!utf8Json.IsEmpty);

    //            _utf8Json = utf8Json;
    //            _parsedData = parsedData;
    //            _extraRentedBytes = extraRentedBytes;

    //            IsDisposable = isDisposable;

    //            // extraRentedBytes better be null if we're not disposable.
    //            Debug.Assert(isDisposable || extraRentedBytes == null);
    //        }
    //        internal bool TryGetNamedPropertyValue(int index, ReadOnlySpan<char> propertyName, out JwtElement value)
    //        {
    //            CheckNotDisposed();

    //            DbRow row = _parsedData.Get(index);

    //            CheckExpectedType(JsonTokenType.StartObject, row.TokenType);

    //            // Only one row means it was EndObject.
    //            if (row.NumberOfRows == 1)
    //            {
    //                value = default;
    //                return false;
    //            }

    //            int maxBytes = Utf8.GetMaxByteCount(propertyName.Length);
    //            int startIndex = index + DbRow.Size;
    //            int endIndex = checked(row.NumberOfRows * DbRow.Size + index);

    //            if (maxBytes < JsonConstants.StackallocThreshold)
    //            {
    //                Span<byte> utf8Name = stackalloc byte[JsonConstants.StackallocThreshold];
    //                int len = JsonReaderHelper.GetUtf8FromText(propertyName, utf8Name);
    //                utf8Name = utf8Name.Slice(0, len);

    //                return TryGetNamedPropertyValue(
    //                    startIndex,
    //                    endIndex,
    //                    utf8Name,
    //                    out value);
    //            }

    //            // Unescaping the property name will make the string shorter (or the same)
    //            // So the first viable candidate is one whose length in bytes matches, or
    //            // exceeds, our length in chars.
    //            //
    //            // The maximal escaping seems to be 6 -> 1 ("\u0030" => "0"), but just transcode
    //            // and switch once one viable long property is found.

    //            int minBytes = propertyName.Length;
    //            // Move to the row before the EndObject
    //            int candidateIndex = endIndex - DbRow.Size;

    //            while (candidateIndex > index)
    //            {
    //                int passedIndex = candidateIndex;

    //                row = _parsedData.Get(candidateIndex);
    //                Debug.Assert(row.TokenType != JsonTokenType.PropertyName);

    //                // Move before the value
    //                if (row.IsSimpleValue)
    //                {
    //                    candidateIndex -= DbRow.Size;
    //                }
    //                else
    //                {
    //                    Debug.Assert(row.NumberOfRows > 0);
    //                    candidateIndex -= DbRow.Size * (row.NumberOfRows + 1);
    //                }

    //                row = _parsedData.Get(candidateIndex);
    //                Debug.Assert(row.TokenType == JsonTokenType.PropertyName);

    //                if (row.SizeOrLength >= minBytes)
    //                {
    //                    byte[] tmpUtf8 = ArrayPool<byte>.Shared.Rent(maxBytes);
    //                    Span<byte> utf8Name = default;

    //                    try
    //                    {
    //                        int len = JsonReaderHelper.GetUtf8FromText(propertyName, tmpUtf8);
    //                        utf8Name = tmpUtf8.AsSpan(0, len);

    //                        return TryGetNamedPropertyValue(
    //                            startIndex,
    //                            passedIndex + DbRow.Size,
    //                            utf8Name,
    //                            out value);
    //                    }
    //                    finally
    //                    {
    //                        // While property names aren't usually a secret, they also usually
    //                        // aren't long enough to end up in the rented buffer transcode path.
    //                        //
    //                        // On the basis that this is user data, go ahead and clear it.
    //                        utf8Name.Clear();
    //                        ArrayPool<byte>.Shared.Return(tmpUtf8);
    //                    }
    //                }

    //                // Move to the previous value
    //                candidateIndex -= DbRow.Size;
    //            }

    //            // None of the property names were within the range that the UTF-8 encoding would have been.
    //            value = default;
    //            return false;
    //        }


    //        internal bool TryGetNamedPropertyValue(int index, ReadOnlySpan<byte> propertyName, out JwtElement value)
    //        {
    //            CheckNotDisposed();

    //            DbRow row = _parsedData.Get(index);

    //            CheckExpectedType(JsonTokenType.StartObject, row.TokenType);

    //            // Only one row means it was EndObject.
    //            if (row.NumberOfRows == 1)
    //            {
    //                value = default;
    //                return false;
    //            }

    //            int endIndex = checked(row.NumberOfRows * DbRow.Size + index);

    //            return TryGetNamedPropertyValue(
    //                index + DbRow.Size,
    //                endIndex,
    //                propertyName,
    //                out value);
    //        }

    //        private bool TryGetNamedPropertyValue(
    //            int startIndex,
    //            int endIndex,
    //            ReadOnlySpan<byte> propertyName,
    //            out JwtElement value)
    //        {
    //            ReadOnlySpan<byte> documentSpan = _utf8Json.Span;
    //            Span<byte> utf8UnescapedStack = stackalloc byte[JsonConstants.StackallocThreshold];

    //            // Move to the row before the EndObject
    //            int index = endIndex - DbRow.Size;

    //            while (index > startIndex)
    //            {
    //                DbRow row = _parsedData.Get(index);
    //                Debug.Assert(row.TokenType != JsonTokenType.PropertyName);

    //                // Move before the value
    //                if (row.IsSimpleValue)
    //                {
    //                    index -= DbRow.Size;
    //                }
    //                else
    //                {
    //                    //       Debug.Assert(row.NumberOfRows > 0);
    //                    index -= DbRow.Size * (row.NumberOfRows + 1);
    //                }

    //                row = _parsedData.Get(index);
    //                Debug.Assert(row.TokenType == JsonTokenType.PropertyName);

    //                ReadOnlySpan<byte> currentPropertyName = documentSpan.Slice(row.Location, row.SizeOrLength);

    //                if (row.HasComplexChildren)
    //                {
    //                    // An escaped property name will be longer than an unescaped candidate, so only unescape
    //                    // when the lengths are compatible.
    //                    if (currentPropertyName.Length > propertyName.Length)
    //                    {
    //                        int idx = currentPropertyName.IndexOf(JsonConstants.BackSlash);
    //                        Debug.Assert(idx >= 0);

    //                        // If everything up to where the property name has a backslash matches, keep going.
    //                        if (propertyName.Length > idx &&
    //                            currentPropertyName.Slice(0, idx).SequenceEqual(propertyName.Slice(0, idx)))
    //                        {
    //                            int remaining = currentPropertyName.Length - idx;
    //                            int written = 0;
    //                            byte[]? rented = null;

    //                            try
    //                            {
    //                                Span<byte> utf8Unescaped = remaining <= utf8UnescapedStack.Length ?
    //                                    utf8UnescapedStack :
    //                                    (rented = ArrayPool<byte>.Shared.Rent(remaining));

    //                                // Only unescape the part we haven't processed.
    //                                JsonReaderHelper.Unescape(currentPropertyName.Slice(idx), utf8Unescaped, 0, out written);

    //                                // If the unescaped remainder matches the input remainder, it's a match.
    //                                if (utf8Unescaped.Slice(0, written).SequenceEqual(propertyName.Slice(idx)))
    //                                {
    //                                    // If the property name is a match, the answer is the next element.
    //                                    value = new JwtElement(this, index + DbRow.Size);
    //                                    return true;
    //                                }
    //                            }
    //                            finally
    //                            {
    //                                if (rented != null)
    //                                {
    //                                    rented.AsSpan(0, written).Clear();
    //                                    ArrayPool<byte>.Shared.Return(rented);
    //                                }
    //                            }
    //                        }
    //                    }
    //                }
    //                else if (currentPropertyName.SequenceEqual(propertyName))
    //                {
    //                    // If the property name is a match, the answer is the next element.
    //                    value = new JwtElement(this, index + DbRow.Size);
    //                    return true;
    //                }

    //                // Move to the previous value
    //                index -= DbRow.Size;
    //            }

    //            value = default;
    //            return false;
    //        }

    //        /// <inheritdoc />
    //        public void Dispose()
    //        {
    //            int length = _utf8Json.Length;
    //            if (length == 0 || !IsDisposable)
    //            {
    //                return;
    //            }

    //            _parsedData.Dispose();
    //            _utf8Json = ReadOnlyMemory<byte>.Empty;

    //            // When "extra rented bytes exist" they contain the document,
    //            // and thus need to be cleared before being returned.
    //            byte[]? extraRentedBytes = Interlocked.Exchange(ref _extraRentedBytes, null);

    //            if (extraRentedBytes != null)
    //            {
    //                extraRentedBytes.AsSpan(0, length).Clear();
    //                ArrayPool<byte>.Shared.Return(extraRentedBytes);
    //            }
    //        }

    //        internal JsonTokenType GetJsonTokenType(int index)
    //        {
    //            CheckNotDisposed();

    //            return _parsedData.GetJsonTokenType(index);
    //        }

    //        private void CheckExpectedType(JsonTokenType expected, JsonTokenType actual)
    //        {
    //            if (expected != actual)
    //            {
    //                //throw ThrowHelper.GetJsonElementWrongTypeException(expected, actual);
    //                throw new InvalidOperationException();
    //            }
    //        }

    //        private void CheckNotDisposed()
    //        {
    //            if (_utf8Json.IsEmpty)
    //            {
    //                throw new ObjectDisposedException(nameof(JsonDocument));
    //            }
    //        }

    //        internal int GetEndIndex(int index, bool includeEndElement)
    //        {
    //            CheckNotDisposed();

    //            DbRow row = _parsedData.Get(index);

    //            if (row.IsSimpleValue)
    //            {
    //                return index + DbRow.Size;
    //            }

    //            int endIndex = index + DbRow.Size * row.NumberOfRows;

    //            if (includeEndElement)
    //            {
    //                endIndex += DbRow.Size;
    //            }

    //            return endIndex;
    //        }

    //        private ReadOnlyMemory<byte> GetRawValue(int index, bool includeQuotes)
    //        {
    //            CheckNotDisposed();

    //            DbRow row = _parsedData.Get(index);

    //            if (row.IsSimpleValue)
    //            {
    //                if (includeQuotes && row.TokenType == JsonTokenType.String)
    //                {
    //                    // Start one character earlier than the value (the open quote)
    //                    // End one character after the value (the close quote)
    //                    return _utf8Json.Slice(row.Location - 1, row.SizeOrLength + 2);
    //                }

    //                return _utf8Json.Slice(row.Location, row.SizeOrLength);
    //            }

    //            int endElementIdx = GetEndIndex(index, includeEndElement: false);
    //            int start = row.Location;
    //            row = _parsedData.Get(endElementIdx);
    //            return _utf8Json.Slice(start, row.Location - start + row.SizeOrLength);
    //        }

    //        private ReadOnlyMemory<byte> GetPropertyRawValue(int valueIndex)
    //        {
    //            CheckNotDisposed();

    //            // The property name is stored one row before the value
    //            DbRow row = _parsedData.Get(valueIndex - DbRow.Size);
    //            Debug.Assert(row.TokenType == JsonTokenType.PropertyName);

    //            // Subtract one for the open quote.
    //            int start = row.Location - 1;
    //            int end;

    //            row = _parsedData.Get(valueIndex);

    //            if (row.IsSimpleValue)
    //            {
    //                end = row.Location + row.SizeOrLength;

    //                // If the value was a string, pick up the terminating quote.
    //                if (row.TokenType == JsonTokenType.String)
    //                {
    //                    end++;
    //                }

    //                return _utf8Json.Slice(start, end - start);
    //            }

    //            int endElementIdx = GetEndIndex(valueIndex, includeEndElement: false);
    //            row = _parsedData.Get(endElementIdx);
    //            end = row.Location + row.SizeOrLength;
    //            return _utf8Json.Slice(start, end - start);
    //        }

    //        internal string? GetString(int index, JsonTokenType expectedType)
    //        {
    //            CheckNotDisposed();

    //            (int lastIdx, string? lastString) = _lastIndexAndString;

    //            if (lastIdx == index)
    //            {
    //                Debug.Assert(lastString != null);
    //                return lastString;
    //            }

    //            DbRow row = _parsedData.Get(index);

    //            JsonTokenType tokenType = row.TokenType;

    //            if (tokenType == JsonTokenType.Null)
    //            {
    //                return null;
    //            }

    //            CheckExpectedType(expectedType, tokenType);

    //            ReadOnlySpan<byte> data = _utf8Json.Span;
    //            ReadOnlySpan<byte> segment = data.Slice(row.Location, row.SizeOrLength);

    //            if (row.HasComplexChildren)
    //            {
    //                int backslash = segment.IndexOf(JsonConstants.BackSlash);
    //                lastString = JsonReaderHelper.GetUnescapedString(segment, backslash);
    //            }
    //            else
    //            {
    //                lastString = JsonReaderHelper.TranscodeHelper(segment);
    //            }

    //            Debug.Assert(lastString != null);
    //            _lastIndexAndString = (index, lastString);
    //            return lastString;
    //        }

    //        internal bool TextEquals(int index, ReadOnlySpan<char> otherText, bool isPropertyName)
    //        {
    //            CheckNotDisposed();

    //            int matchIndex = isPropertyName ? index - DbRow.Size : index;

    //            (int lastIdx, string? lastString) = _lastIndexAndString;

    //            if (lastIdx == matchIndex)
    //            {
    //                return otherText.SequenceEqual(lastString.AsSpan());
    //            }

    //            byte[]? otherUtf8TextArray = null;

    //            int length = checked(otherText.Length * JsonConstants.MaxExpansionFactorWhileTranscoding);
    //            Span<byte> otherUtf8Text = length <= JsonConstants.StackallocThreshold ?
    //                stackalloc byte[JsonConstants.StackallocThreshold] :
    //                (otherUtf8TextArray = ArrayPool<byte>.Shared.Rent(length));

    //            ReadOnlySpan<byte> utf16Text = MemoryMarshal.AsBytes(otherText);
    //            OperationStatus status = JsonReaderHelper.ToUtf8(utf16Text, otherUtf8Text, out int consumed, out int written);
    //            Debug.Assert(status != OperationStatus.DestinationTooSmall);
    //            bool result;
    //            if (status > OperationStatus.DestinationTooSmall)   // Equivalent to: (status == NeedMoreData || status == InvalidData)
    //            {
    //                result = false;
    //            }
    //            else
    //            {
    //                Debug.Assert(status == OperationStatus.Done);
    //                Debug.Assert(consumed == utf16Text.Length);

    //                result = TextEquals(index, otherUtf8Text.Slice(0, written), isPropertyName, shouldUnescape: true);
    //            }

    //            if (otherUtf8TextArray != null)
    //            {
    //                otherUtf8Text.Slice(0, written).Clear();
    //                ArrayPool<byte>.Shared.Return(otherUtf8TextArray);
    //            }

    //            return result;
    //        }

    //        internal bool TextEquals(int index, ReadOnlySpan<byte> otherUtf8Text, bool isPropertyName, bool shouldUnescape)
    //        {
    //            CheckNotDisposed();

    //            int matchIndex = isPropertyName ? index - DbRow.Size : index;

    //            DbRow row = _parsedData.Get(matchIndex);

    //            CheckExpectedType(
    //                isPropertyName ? JsonTokenType.PropertyName : JsonTokenType.String,
    //                row.TokenType);

    //            ReadOnlySpan<byte> data = _utf8Json.Span;
    //            ReadOnlySpan<byte> segment = data.Slice(row.Location, row.SizeOrLength);

    //            if (otherUtf8Text.Length > segment.Length || (!shouldUnescape && otherUtf8Text.Length != segment.Length))
    //            {
    //                return false;
    //            }

    //            if (row.HasComplexChildren && shouldUnescape)
    //            {
    //                if (otherUtf8Text.Length < segment.Length / JsonConstants.MaxExpansionFactorWhileEscaping)
    //                {
    //                    return false;
    //                }

    //                int idx = segment.IndexOf(JsonConstants.BackSlash);
    //                Debug.Assert(idx != -1);

    //                if (!otherUtf8Text.StartsWith(segment.Slice(0, idx)))
    //                {
    //                    return false;
    //                }

    //                return JsonReaderHelper.UnescapeAndCompare(segment.Slice(idx), otherUtf8Text.Slice(idx));
    //            }

    //            return segment.SequenceEqual(otherUtf8Text);
    //        }

    //        internal string GetNameOfPropertyValue(int index)
    //        {
    //            // The property name is one row before the property value
    //            return GetString(index - DbRow.Size, JsonTokenType.PropertyName)!;
    //        }

    //        internal bool TryGetValue(int index, out long value)
    //        {
    //            CheckNotDisposed();

    //            DbRow row = _parsedData.Get(index);

    //            CheckExpectedType(JsonTokenType.Number, row.TokenType);

    //            ReadOnlySpan<byte> data = _utf8Json.Span;
    //            ReadOnlySpan<byte> segment = data.Slice(row.Location, row.SizeOrLength);

    //            if (Utf8Parser.TryParse(segment, out long tmp, out int consumed) &&
    //                consumed == segment.Length)
    //            {
    //                value = tmp;
    //                return true;
    //            }

    //            value = 0;
    //            return false;
    //        }

    //        internal bool TryGetValue(int index, out double value)
    //        {
    //            CheckNotDisposed();

    //            DbRow row = _parsedData.Get(index);

    //            CheckExpectedType(JsonTokenType.Number, row.TokenType);

    //            ReadOnlySpan<byte> data = _utf8Json.Span;
    //            ReadOnlySpan<byte> segment = data.Slice(row.Location, row.SizeOrLength);

    //            if (Utf8Parser.TryParse(segment, out double tmp, out int bytesConsumed) &&
    //                segment.Length == bytesConsumed)
    //            {
    //                value = tmp;
    //                return true;
    //            }

    //            value = 0;
    //            return false;
    //        }
    //        internal bool TryGetValue(int index, out JsonDocument? value)
    //        {
    //            CheckNotDisposed();

    //            DbRow row = _parsedData.Get(index);

    //            CheckExpectedType(JsonTokenType.StartObject, row.TokenType);

    //            ReadOnlySpan<byte> data = _utf8Json.Span;
    //            ReadOnlySpan<byte> segment = data.Slice(row.Location, row.SizeOrLength);
    //            var reader = new Utf8JsonReader(segment);

    //            if (JsonDocument.TryParseValue(ref reader, out var tmp))
    //            {
    //                value = tmp;
    //                return true;
    //            }

    //            value = null;
    //            return false;
    //        }

    //        internal string GetRawValueAsString(int index)
    //        {
    //            ReadOnlyMemory<byte> segment = GetRawValue(index, includeQuotes: true);
    //            return JsonReaderHelper.TranscodeHelper(segment.Span);
    //        }

    //        internal string GetPropertyRawValueAsString(int valueIndex)
    //        {
    //            ReadOnlyMemory<byte> segment = GetPropertyRawValue(valueIndex);
    //            return JsonReaderHelper.TranscodeHelper(segment.Span);
    //        }

    //        internal JwtElement CloneElement(int index)
    //        {
    //            int endIndex = GetEndIndex(index, true);
    //            MetadataDb newDb = _parsedData.CopySegment(index, endIndex);
    //            ReadOnlyMemory<byte> segmentCopy = GetRawValue(index, includeQuotes: true).ToArray();

    //            JwtPayloadDocument newDocument = new JwtPayloadDocument(segmentCopy, newDb, extraRentedBytes: null, isDisposable: false);

    //            return newDocument.RootElement;
    //        }

    //        public static JwtPayloadDocument Parse(ReadOnlyMemory<byte> utf8Json, TokenValidationPolicy policy, JsonReaderOptions options = default)
    //                => Parse(utf8Json, options, policy, null);

    //        private static JwtPayloadDocument Parse(
    //          ReadOnlyMemory<byte> utf8Json,
    //          JsonReaderOptions readerOptions,
    //          TokenValidationPolicy policy,
    //          byte[]? extraRentedBytes)
    //        {
    //            ReadOnlySpan<byte> utf8JsonSpan = utf8Json.Span;
    //            var database = new MetadataDb(utf8Json.Length);
    //            var stack = new StackRowStack(64 * StackRow.Size);

    //            try
    //            {
    //                Parse(utf8JsonSpan, readerOptions, policy, ref database, ref stack);
    //            }
    //            catch
    //            {
    //                database.Dispose();
    //                throw;
    //            }
    //            finally
    //            {
    //                stack.Dispose();
    //            }

    //            return new JwtPayloadDocument(utf8Json, database, extraRentedBytes);
    //        }

    //        private static void Parse(
    //            ReadOnlySpan<byte> utf8JsonSpan,
    //            JsonReaderOptions readerOptions,
    //            TokenValidationPolicy policy,
    //            ref MetadataDb database,
    //            ref StackRowStack stack)
    //        {
    //            bool inArray = false;
    //            int arrayItemsCount = 0;
    //            int numberOfRowsForMembers = 0;
    //            int numberOfRowsForValues = 0;

    //            //var reader = new JwtPayloadDocumentReader(utf8JsonSpan, policy);
    //            Utf8JsonReader reader = new Utf8JsonReader(
    //                utf8JsonSpan,
    //                isFinalBlock: true,
    //                new JsonReaderState(options: readerOptions));
    //            if (reader.Read() && reader.TokenType == JsonTokenType.StartObject)
    //            {
    //                numberOfRowsForValues++;
    //                database.Append(reader.TokenType, (int)reader.TokenStartIndex, DbRow.UnknownSize);
    //                var row = new StackRow(numberOfRowsForMembers + 1);
    //                stack.Push(row);
    //                numberOfRowsForMembers = 0;

    //                while (reader.Read())
    //                {
    //                    JsonTokenType tokenType = reader.TokenType;

    //                    // Since the input payload is contained within a Span,
    //                    // token start index can never be larger than int.MaxValue (i.e. utf8JsonSpan.Length).
    //                    Debug.Assert(reader.TokenStartIndex <= int.MaxValue);
    //                    int tokenStart = (int)reader.TokenStartIndex;

    //                    if (tokenType == JsonTokenType.StartObject)
    //                    {
    //                        //numberOfRowsForValues++;
    //                        //database.Append(tokenType, tokenStart, DbRow.UnknownSize);
    //                        //row = new StackRow(numberOfRowsForMembers + 1);
    //                        //stack.Push(row);
    //                        //numberOfRowsForMembers = 0;
    //                        numberOfRowsForValues++;
    //                        numberOfRowsForMembers++;

    //                        if (inArray)
    //                        {
    //                            arrayItemsCount++;
    //                        }

    //                        reader.Skip();
    //                        int tokenEnd = (int)reader.TokenStartIndex + 1;
    //                        database.Append(tokenType, tokenStart, tokenEnd - tokenStart);
    //                    }
    //                    else if (tokenType == JsonTokenType.EndObject)
    //                    {
    //                        int rowIndex = database.FindIndexOfFirstUnsetSizeOrLength(JsonTokenType.StartObject);

    //                        numberOfRowsForValues++;
    //                        numberOfRowsForMembers++;
    //                        database.SetLength(rowIndex, numberOfRowsForMembers);

    //                        int newRowIndex = database.Length;
    //                        database.Append(tokenType, tokenStart, reader.ValueSpan.Length);
    //                        database.SetNumberOfRows(rowIndex, numberOfRowsForMembers);
    //                        database.SetNumberOfRows(newRowIndex, numberOfRowsForMembers);

    //                        row = stack.Pop();
    //                        numberOfRowsForMembers += row.SizeOrLength;
    //                    }
    //                    else if (tokenType == JsonTokenType.StartArray)
    //                    {
    //                        //if (inArray)
    //                        //{
    //                        //    arrayItemsCount++;
    //                        //}
    //                        numberOfRowsForMembers++;

    //                        reader.Skip();
    //                        int tokenEnd = (int)reader.TokenStartIndex + 1;
    //                        database.Append(tokenType, tokenStart, tokenEnd - tokenStart);
    //                        arrayItemsCount = 0;
    //                        numberOfRowsForValues = 0;
    //                    }
    //                    else if (tokenType == JsonTokenType.EndArray)
    //                    {
    //                        int rowIndex = database.FindIndexOfFirstUnsetSizeOrLength(JsonTokenType.StartArray);

    //                        numberOfRowsForValues++;
    //                        numberOfRowsForMembers++;
    //                        database.SetLength(rowIndex, arrayItemsCount);
    //                        database.SetNumberOfRows(rowIndex, numberOfRowsForValues);

    //                        // If the array item count is (e.g.) 12 and the number of rows is (e.g.) 13
    //                        // then the extra row is just this EndArray item, so the array was made up
    //                        // of simple values.
    //                        //
    //                        // If the off-by-one relationship does not hold, then one of the values was
    //                        // more than one row, making it a complex object.
    //                        //
    //                        // This check is similar to tracking the start array and painting it when
    //                        // StartObject or StartArray is encountered, but avoids the mixed state
    //                        // where "UnknownSize" implies "has complex children".
    //                        if (arrayItemsCount + 1 != numberOfRowsForValues)
    //                        {
    //                            database.SetHasComplexChildren(rowIndex);
    //                        }

    //                        int newRowIndex = database.Length;
    //                        database.Append(tokenType, tokenStart, reader.ValueSpan.Length);
    //                        database.SetNumberOfRows(newRowIndex, numberOfRowsForValues);

    //                        row = stack.Pop();
    //                        arrayItemsCount = row.SizeOrLength;
    //                        numberOfRowsForValues += row.NumberOfRows;
    //                    }
    //                    else if (tokenType == JsonTokenType.PropertyName)
    //                    {
    //                        numberOfRowsForValues++;
    //                        numberOfRowsForMembers++;

    //                        // Adding 1 to skip the start quote will never overflow
    //                        Debug.Assert(tokenStart < int.MaxValue);

    //                        database.Append(tokenType, tokenStart + 1, reader.ValueSpan.Length);

    //                        //if (reader._stringHasEscaping)
    //                        //{
    //                        //    database.SetHasComplexChildren(database.Length - DbRow.Size);
    //                        //}

    //                        Debug.Assert(!inArray);
    //                    }
    //                    else
    //                    {
    //                        Debug.Assert(tokenType >= JsonTokenType.String && tokenType <= JsonTokenType.Null);
    //                        numberOfRowsForValues++;
    //                        numberOfRowsForMembers++;

    //                        if (inArray)
    //                        {
    //                            arrayItemsCount++;
    //                        }

    //                        if (tokenType == JsonTokenType.String)
    //                        {
    //                            // Adding 1 to skip the start quote will never overflow
    //                            Debug.Assert(tokenStart < int.MaxValue);

    //                            database.Append(tokenType, tokenStart + 1, reader.ValueSpan.Length);

    //                            //if (reader._stringHasEscaping)
    //                            //{
    //                            //    database.SetHasComplexChildren(database.Length - DbRow.Size);
    //                            //}
    //                        }
    //                        else
    //                        {
    //                            database.Append(tokenType, tokenStart, reader.ValueSpan.Length);
    //                        }
    //                    }

    //                    //  inArray = reader.IsInArray;
    //                }
    //            }

    //            //Debug.Assert(reader.BytesConsumed == utf8JsonSpan.Length);
    //            database.TrimExcess();
    //        }

    //        internal int GetArrayLength(int index)
    //        {
    //            CheckNotDisposed();

    //            DbRow row = _parsedData.Get(index);

    //            CheckExpectedType(JsonTokenType.StartArray, row.TokenType);

    //            return row.SizeOrLength;
    //        }

    //        internal JwtElement GetArrayIndexElement(int currentIndex, int arrayIndex)
    //        {
    //            CheckNotDisposed();

    //            DbRow row = _parsedData.Get(currentIndex);

    //            CheckExpectedType(JsonTokenType.StartArray, row.TokenType);

    //            int arrayLength = row.SizeOrLength;

    //            if ((uint)arrayIndex >= (uint)arrayLength)
    //            {
    //                throw new IndexOutOfRangeException();
    //            }

    //            if (!row.HasComplexChildren)
    //            {
    //                // Since we wouldn't be here without having completed the document parse, and we
    //                // already vetted the index against the length, this new index will always be
    //                // within the table.
    //                return new JwtElement(this, currentIndex + ((arrayIndex + 1) * DbRow.Size));
    //            }

    //            int elementCount = 0;
    //            int objectOffset = currentIndex + DbRow.Size;

    //            for (; objectOffset < _parsedData.Length; objectOffset += DbRow.Size)
    //            {
    //                if (arrayIndex == elementCount)
    //                {
    //                    return new JwtElement(this, objectOffset);
    //                }

    //                row = _parsedData.Get(objectOffset);

    //                if (!row.IsSimpleValue)
    //                {
    //                    objectOffset += DbRow.Size * row.NumberOfRows;
    //                }

    //                elementCount++;
    //            }

    //            Debug.Fail(
    //                $"Ran out of database searching for array index {arrayIndex} from {currentIndex} when length was {arrayLength}");
    //            throw new IndexOutOfRangeException();
    //        }
    //    }


    //    /// <summary>
    //    ///   Represents a specific JSON value within a <see cref="JwtPayloadDocument"/>.
    //    /// </summary>
    //    [DebuggerDisplay("{DebuggerDisplay,nq}")]
    //    public readonly partial struct JwtElement
    //    {
    //        private readonly JwtPayloadDocument _parent;
    //        private readonly int _idx;

    //        internal JwtElement(JwtPayloadDocument parent, int idx)
    //        {
    //            // parent is usually not null, but the Current property
    //            // on the enumerators (when initialized as `default`) can
    //            // get here with a null.
    //            Debug.Assert(idx >= 0);

    //            _parent = parent;
    //            _idx = idx;
    //        }

    //        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
    //        private JsonTokenType TokenType
    //        {
    //            get
    //            {
    //                return _parent?.GetJsonTokenType(_idx) ?? JsonTokenType.None;
    //            }
    //        }
    //        /// <summary>
    //        ///   The <see cref="JsonValueKind"/> that the value is.
    //        /// </summary>
    //        /// <exception cref="ObjectDisposedException">
    //        ///   The parent <see cref="JsonDocument"/> has been disposed.
    //        /// </exception>
    //        public JsonValueKind ValueKind => ToValueKind(TokenType);

    //        /// <summary>
    //        ///   Get the value at a specified index when the current value is a
    //        ///   <see cref="JsonValueKind.Array"/>.
    //        /// </summary>
    //        /// <exception cref="InvalidOperationException">
    //        ///   This value's <see cref="ValueKind"/> is not <see cref="JsonValueKind.Array"/>.
    //        /// </exception>
    //        /// <exception cref="IndexOutOfRangeException">
    //        ///   <paramref name="index"/> is not in the range [0, <see cref="GetArrayLength"/>()).
    //        /// </exception>
    //        /// <exception cref="ObjectDisposedException">
    //        ///   The parent <see cref="JsonDocument"/> has been disposed.
    //        /// </exception>
    //        public JwtElement this[int index]
    //        {
    //            get
    //            {
    //                CheckValidInstance();

    //                return _parent.GetArrayIndexElement(_idx, index);
    //            }
    //        }

    //        /// <summary>
    //        ///   Get the number of values contained within the current array value.
    //        /// </summary>
    //        /// <returns>The number of values contained within the current array value.</returns>
    //        /// <exception cref="InvalidOperationException">
    //        ///   This value's <see cref="ValueKind"/> is not <see cref="JsonValueKind.Array"/>.
    //        /// </exception>
    //        /// <exception cref="ObjectDisposedException">
    //        ///   The parent <see cref="JsonDocument"/> has been disposed.
    //        /// </exception>
    //        public int GetArrayLength()
    //        {
    //            CheckValidInstance();

    //            return _parent.GetArrayLength(_idx);
    //        }

    //        /// <summary>
    //        ///   Gets a <see cref="JwtElement"/> representing the value of a required property identified
    //        ///   by <paramref name="propertyName"/>.
    //        /// </summary>
    //        /// <remarks>
    //        ///   Property name matching is performed as an ordinal, case-sensitive, comparison.
    //        ///
    //        ///   If a property is defined multiple times for the same object, the last such definition is
    //        ///   what is matched.
    //        /// </remarks>
    //        /// <param name="propertyName">Name of the property whose value to return.</param>
    //        /// <returns>
    //        ///   A <see cref="JwtElement"/> representing the value of the requested property.
    //        /// </returns>
    //        /// <seealso cref="EnumerateObject"/>
    //        /// <exception cref="InvalidOperationException">
    //        ///   This value's <see cref="ValueKind"/> is not <see cref="JsonValueKind.Object"/>.
    //        /// </exception>
    //        /// <exception cref="KeyNotFoundException">
    //        ///   No property was found with the requested name.
    //        /// </exception>
    //        /// <exception cref="ArgumentNullException">
    //        ///   <paramref name="propertyName"/> is <see langword="null"/>.
    //        /// </exception>
    //        /// <exception cref="ObjectDisposedException">
    //        ///   The parent <see cref="JsonDocument"/> has been disposed.
    //        /// </exception>
    //        public JwtElement GetProperty(string propertyName)
    //        {
    //            if (propertyName == null)
    //                throw new ArgumentNullException(nameof(propertyName));

    //            if (TryGetProperty(propertyName, out JwtElement property))
    //            {
    //                return property;
    //            }

    //            throw new KeyNotFoundException();
    //        }

    //        /// <summary>
    //        ///   Gets a <see cref="JwtElement"/> representing the value of a required property identified
    //        ///   by <paramref name="propertyName"/>.
    //        /// </summary>
    //        /// <remarks>
    //        ///   <para>
    //        ///     Property name matching is performed as an ordinal, case-sensitive, comparison.
    //        ///   </para>
    //        ///
    //        ///   <para>
    //        ///     If a property is defined multiple times for the same object, the last such definition is
    //        ///     what is matched.
    //        ///   </para>
    //        /// </remarks>
    //        /// <param name="propertyName">Name of the property whose value to return.</param>
    //        /// <returns>
    //        ///   A <see cref="JwtElement"/> representing the value of the requested property.
    //        /// </returns>
    //        /// <seealso cref="EnumerateObject"/>
    //        /// <exception cref="InvalidOperationException">
    //        ///   This value's <see cref="ValueKind"/> is not <see cref="JsonValueKind.Object"/>.
    //        /// </exception>
    //        /// <exception cref="KeyNotFoundException">
    //        ///   No property was found with the requested name.
    //        /// </exception>
    //        /// <exception cref="ObjectDisposedException">
    //        ///   The parent <see cref="JsonDocument"/> has been disposed.
    //        /// </exception>
    //        public JwtElement GetProperty(ReadOnlySpan<char> propertyName)
    //        {
    //            if (TryGetProperty(propertyName, out JwtElement property))
    //            {
    //                return property;
    //            }

    //            throw new KeyNotFoundException();
    //        }

    //        /// <summary>
    //        ///   Gets a <see cref="JwtElement"/> representing the value of a required property identified
    //        ///   by <paramref name="utf8PropertyName"/>.
    //        /// </summary>
    //        /// <remarks>
    //        ///   <para>
    //        ///     Property name matching is performed as an ordinal, case-sensitive, comparison.
    //        ///   </para>
    //        ///
    //        ///   <para>
    //        ///     If a property is defined multiple times for the same object, the last such definition is
    //        ///     what is matched.
    //        ///   </para>
    //        /// </remarks>
    //        /// <param name="utf8PropertyName">
    //        ///   The UTF-8 (with no Byte-Order-Mark (BOM)) representation of the name of the property to return.
    //        /// </param>
    //        /// <returns>
    //        ///   A <see cref="JwtElement"/> representing the value of the requested property.
    //        /// </returns>
    //        /// <exception cref="InvalidOperationException">
    //        ///   This value's <see cref="ValueKind"/> is not <see cref="JsonValueKind.Object"/>.
    //        /// </exception>
    //        /// <exception cref="KeyNotFoundException">
    //        ///   No property was found with the requested name.
    //        /// </exception>
    //        /// <exception cref="ObjectDisposedException">
    //        ///   The parent <see cref="JsonDocument"/> has been disposed.
    //        /// </exception>
    //        /// <seealso cref="EnumerateObject"/>
    //        public JwtElement GetProperty(ReadOnlySpan<byte> utf8PropertyName)
    //        {
    //            if (TryGetProperty(utf8PropertyName, out JwtElement property))
    //            {
    //                return property;
    //            }

    //            throw new KeyNotFoundException();
    //        }

    //        /// <summary>
    //        ///   Looks for a property named <paramref name="propertyName"/> in the current object, returning
    //        ///   whether or not such a property existed. When the property exists <paramref name="value"/>
    //        ///   is assigned to the value of that property.
    //        /// </summary>
    //        /// <remarks>
    //        ///   <para>
    //        ///     Property name matching is performed as an ordinal, case-sensitive, comparison.
    //        ///   </para>
    //        ///
    //        ///   <para>
    //        ///     If a property is defined multiple times for the same object, the last such definition is
    //        ///     what is matched.
    //        ///   </para>
    //        /// </remarks>
    //        /// <param name="propertyName">Name of the property to find.</param>
    //        /// <param name="value">Receives the value of the located property.</param>
    //        /// <returns>
    //        ///   <see langword="true"/> if the property was found, <see langword="false"/> otherwise.
    //        /// </returns>
    //        /// <exception cref="InvalidOperationException">
    //        ///   This value's <see cref="ValueKind"/> is not <see cref="JsonValueKind.Object"/>.
    //        /// </exception>
    //        /// <exception cref="ArgumentNullException">
    //        ///   <paramref name="propertyName"/> is <see langword="null"/>.
    //        /// </exception>
    //        /// <exception cref="ObjectDisposedException">
    //        ///   The parent <see cref="JsonDocument"/> has been disposed.
    //        /// </exception>
    //        /// <seealso cref="EnumerateObject"/>
    //        public bool TryGetProperty(string propertyName, out JwtElement value)
    //        {
    //            if (propertyName == null)
    //                throw new ArgumentNullException(nameof(propertyName));

    //            return TryGetProperty(propertyName.AsSpan(), out value);
    //        }

    //        /// <summary>
    //        ///   Looks for a property named <paramref name="propertyName"/> in the current object, returning
    //        ///   whether or not such a property existed. When the property exists <paramref name="value"/>
    //        ///   is assigned to the value of that property.
    //        /// </summary>
    //        /// <remarks>
    //        ///   <para>
    //        ///     Property name matching is performed as an ordinal, case-sensitive, comparison.
    //        ///   </para>
    //        ///
    //        ///   <para>
    //        ///     If a property is defined multiple times for the same object, the last such definition is
    //        ///     what is matched.
    //        ///   </para>
    //        /// </remarks>
    //        /// <param name="propertyName">Name of the property to find.</param>
    //        /// <param name="value">Receives the value of the located property.</param>
    //        /// <returns>
    //        ///   <see langword="true"/> if the property was found, <see langword="false"/> otherwise.
    //        /// </returns>
    //        /// <seealso cref="EnumerateObject"/>
    //        /// <exception cref="InvalidOperationException">
    //        ///   This value's <see cref="ValueKind"/> is not <see cref="JsonValueKind.Object"/>.
    //        /// </exception>
    //        /// <exception cref="ObjectDisposedException">
    //        ///   The parent <see cref="JsonDocument"/> has been disposed.
    //        /// </exception>
    //        public bool TryGetProperty(ReadOnlySpan<char> propertyName, out JwtElement value)
    //        {
    //            CheckValidInstance();

    //            return _parent.TryGetNamedPropertyValue(_idx, propertyName, out value);
    //        }

    //        /// <summary>
    //        ///   Looks for a property named <paramref name="utf8PropertyName"/> in the current object, returning
    //        ///   whether or not such a property existed. When the property exists <paramref name="value"/>
    //        ///   is assigned to the value of that property.
    //        /// </summary>
    //        /// <remarks>
    //        ///   <para>
    //        ///     Property name matching is performed as an ordinal, case-sensitive, comparison.
    //        ///   </para>
    //        ///
    //        ///   <para>
    //        ///     If a property is defined multiple times for the same object, the last such definition is
    //        ///     what is matched.
    //        ///   </para>
    //        /// </remarks>
    //        /// <param name="utf8PropertyName">
    //        ///   The UTF-8 (with no Byte-Order-Mark (BOM)) representation of the name of the property to return.
    //        /// </param>
    //        /// <param name="value">Receives the value of the located property.</param>
    //        /// <returns>
    //        ///   <see langword="true"/> if the property was found, <see langword="false"/> otherwise.
    //        /// </returns>
    //        /// <seealso cref="EnumerateObject"/>
    //        /// <exception cref="InvalidOperationException">
    //        ///   This value's <see cref="ValueKind"/> is not <see cref="JsonValueKind.Object"/>.
    //        /// </exception>
    //        /// <exception cref="ObjectDisposedException">
    //        ///   The parent <see cref="JsonDocument"/> has been disposed.
    //        /// </exception>
    //        public bool TryGetProperty(ReadOnlySpan<byte> utf8PropertyName, out JwtElement value)
    //        {
    //            CheckValidInstance();

    //            return _parent.TryGetNamedPropertyValue(_idx, utf8PropertyName, out value);
    //        }

    //        /// <summary>
    //        ///   Gets the value of the element as a <see cref="bool"/>.
    //        /// </summary>
    //        /// <remarks>
    //        ///   This method does not parse the contents of a JSON string value.
    //        /// </remarks>
    //        /// <returns>The value of the element as a <see cref="bool"/>.</returns>
    //        /// <exception cref="InvalidOperationException">
    //        ///   This value's <see cref="ValueKind"/> is neither <see cref="JsonValueKind.True"/> or
    //        ///   <see cref="JsonValueKind.False"/>.
    //        /// </exception>
    //        /// <exception cref="ObjectDisposedException">
    //        ///   The parent <see cref="JsonDocument"/> has been disposed.
    //        /// </exception>
    //        public bool GetBoolean()
    //        {
    //            // CheckValidInstance is redundant.  Asking for the type will
    //            // return None, which then throws the same exception in the return statement.

    //            JsonTokenType type = TokenType;

    //            return
    //                type == JsonTokenType.True ? true :
    //                type == JsonTokenType.False ? false :
    //                throw ThrowHelper.CreateInvalidOperationException_NotSupportedJsonType(/*nameof(Boolean), type*/JwtTokenType.Boolean);
    //        }

    //        /// <summary>
    //        ///   Gets the value of the element as a <see cref="string"/>.
    //        /// </summary>
    //        /// <remarks>
    //        ///   This method does not create a string representation of values other than JSON strings.
    //        /// </remarks>
    //        /// <returns>The value of the element as a <see cref="string"/>.</returns>
    //        /// <exception cref="InvalidOperationException">
    //        ///   This value's <see cref="ValueKind"/> is neither <see cref="JsonValueKind.String"/> nor <see cref="JsonValueKind.Null"/>.
    //        /// </exception>
    //        /// <exception cref="ObjectDisposedException">
    //        ///   The parent <see cref="JsonDocument"/> has been disposed.
    //        /// </exception>
    //        /// <seealso cref="ToString"/>
    //        public string? GetString()
    //        {
    //            CheckValidInstance();

    //            return _parent.GetString(_idx, JsonTokenType.String);
    //        }

    //        /// <summary>
    //        ///   Attempts to represent the current JSON number as a <see cref="long"/>.
    //        /// </summary>
    //        /// <param name="value">Receives the value.</param>
    //        /// <remarks>
    //        ///   This method does not parse the contents of a JSON string value.
    //        /// </remarks>
    //        /// <returns>
    //        ///   <see langword="true"/> if the number can be represented as a <see cref="long"/>,
    //        ///   <see langword="false"/> otherwise.
    //        /// </returns>
    //        /// <exception cref="InvalidOperationException">
    //        ///   This value's <see cref="ValueKind"/> is not <see cref="JsonValueKind.Number"/>.
    //        /// </exception>
    //        /// <exception cref="ObjectDisposedException">
    //        ///   The parent <see cref="JsonDocument"/> has been disposed.
    //        /// </exception>
    //        public bool TryGetInt64(out long value)
    //        {
    //            CheckValidInstance();

    //            return _parent.TryGetValue(_idx, out value);
    //        }

    //        /// <summary>
    //        ///   Gets the current JSON number as a <see cref="long"/>.
    //        /// </summary>
    //        /// <returns>The current JSON number as a <see cref="long"/>.</returns>
    //        /// <remarks>
    //        ///   This method does not parse the contents of a JSON string value.
    //        /// </remarks>
    //        /// <exception cref="InvalidOperationException">
    //        ///   This value's <see cref="ValueKind"/> is not <see cref="JsonValueKind.Number"/>.
    //        /// </exception>
    //        /// <exception cref="FormatException">
    //        ///   The value cannot be represented as a <see cref="long"/>.
    //        /// </exception>
    //        /// <exception cref="ObjectDisposedException">
    //        ///   The parent <see cref="JsonDocument"/> has been disposed.
    //        /// </exception>
    //        public long GetInt64()
    //        {
    //            if (TryGetInt64(out long value))
    //            {
    //                return value;
    //            }

    //            throw ThrowHelper.CreateFormatException_MalformedJson();
    //        }

    //        /// <summary>
    //        ///   Attempts to represent the current JSON number as a <see cref="double"/>.
    //        /// </summary>
    //        /// <param name="value">Receives the value.</param>
    //        /// <remarks>
    //        ///   <para>
    //        ///     This method does not parse the contents of a JSON string value.
    //        ///   </para>
    //        ///
    //        ///   <para>
    //        ///     On .NET Core this method does not return <see langword="false"/> for values larger than
    //        ///     <see cref="double.MaxValue"/> (or smaller than <see cref="double.MinValue"/>),
    //        ///     instead <see langword="true"/> is returned and <see cref="double.PositiveInfinity"/> (or
    //        ///     <see cref="double.NegativeInfinity"/>) is emitted.
    //        ///   </para>
    //        /// </remarks>
    //        /// <returns>
    //        ///   <see langword="true"/> if the number can be represented as a <see cref="double"/>,
    //        ///   <see langword="false"/> otherwise.
    //        /// </returns>
    //        /// <exception cref="InvalidOperationException">
    //        ///   This value's <see cref="ValueKind"/> is not <see cref="JsonValueKind.Number"/>.
    //        /// </exception>
    //        /// <exception cref="ObjectDisposedException">
    //        ///   The parent <see cref="JsonDocument"/> has been disposed.
    //        /// </exception>
    //        public bool TryGetDouble(out double value)
    //        {
    //            CheckValidInstance();

    //            return _parent.TryGetValue(_idx, out value);
    //        }

    //        public bool TryGetJsonDocument(out JsonDocument? value)
    //        {
    //            CheckValidInstance();

    //            return _parent.TryGetValue(_idx, out value);
    //        }

    //        /// <summary>
    //        ///   Gets the current JSON number as a <see cref="double"/>.
    //        /// </summary>
    //        /// <returns>The current JSON number as a <see cref="double"/>.</returns>
    //        /// <remarks>
    //        ///   <para>
    //        ///     This method does not parse the contents of a JSON string value.
    //        ///   </para>
    //        ///
    //        ///   <para>
    //        ///     On .NET Core this method returns <see cref="double.PositiveInfinity"/> (or
    //        ///     <see cref="double.NegativeInfinity"/>) for values larger than
    //        ///     <see cref="double.MaxValue"/> (or smaller than <see cref="double.MinValue"/>).
    //        ///   </para>
    //        /// </remarks>
    //        /// <exception cref="InvalidOperationException">
    //        ///   This value's <see cref="ValueKind"/> is not <see cref="JsonValueKind.Number"/>.
    //        /// </exception>
    //        /// <exception cref="FormatException">
    //        ///   The value cannot be represented as a <see cref="double"/>.
    //        /// </exception>
    //        /// <exception cref="ObjectDisposedException">
    //        ///   The parent <see cref="JsonDocument"/> has been disposed.
    //        /// </exception>
    //        public double GetDouble()
    //        {
    //            if (TryGetDouble(out double value))
    //            {
    //                return value;
    //            }

    //            throw ThrowHelper.CreateFormatException_MalformedJson();
    //        }

    //        public JsonDocument GetJsonDocument()
    //        {
    //            if (TryGetJsonDocument(out JsonDocument value))
    //            {
    //                return value;
    //            }

    //            throw ThrowHelper.CreateFormatException_MalformedJson();
    //        }

    //        internal string GetPropertyName()
    //        {
    //            CheckValidInstance();

    //            return _parent.GetNameOfPropertyValue(_idx);
    //        }

    //        /// <summary>
    //        ///   Gets the original input data backing this value, returning it as a <see cref="string"/>.
    //        /// </summary>
    //        /// <returns>
    //        ///   The original input data backing this value, returning it as a <see cref="string"/>.
    //        /// </returns>
    //        /// <exception cref="ObjectDisposedException">
    //        ///   The parent <see cref="JwtPayloadDocument"/> has been disposed.
    //        /// </exception>
    //        public string GetRawText()
    //        {
    //            CheckValidInstance();

    //            return _parent.GetRawValueAsString(_idx);
    //        }

    //        internal string GetPropertyRawText()
    //        {
    //            CheckValidInstance();

    //            return _parent.GetPropertyRawValueAsString(_idx);
    //        }

    //        /// <summary>
    //        ///   Compares <paramref name="text" /> to the string value of this element.
    //        /// </summary>
    //        /// <param name="text">The text to compare against.</param>
    //        /// <returns>
    //        ///   <see langword="true" /> if the string value of this element matches <paramref name="text"/>,
    //        ///   <see langword="false" /> otherwise.
    //        /// </returns>
    //        /// <exception cref="InvalidOperationException">
    //        ///   This value's <see cref="ValueKind"/> is not <see cref="JsonValueKind.String"/>.
    //        /// </exception>
    //        /// <remarks>
    //        ///   This method is functionally equal to doing an ordinal comparison of <paramref name="text" /> and
    //        ///   the result of calling <see cref="GetString" />, but avoids creating the string instance.
    //        /// </remarks>
    //        public bool ValueEquals(string? text)
    //        {
    //            // CheckValidInstance is done in the helper

    //            if (TokenType == JsonTokenType.Null)
    //            {
    //                return text == null;
    //            }

    //            return TextEqualsHelper(text.AsSpan(), isPropertyName: false);
    //        }

    //        /// <summary>
    //        ///   Compares the text represented by <paramref name="utf8Text" /> to the string value of this element.
    //        /// </summary>
    //        /// <param name="utf8Text">The UTF-8 encoded text to compare against.</param>
    //        /// <returns>
    //        ///   <see langword="true" /> if the string value of this element has the same UTF-8 encoding as
    //        ///   <paramref name="utf8Text" />, <see langword="false" /> otherwise.
    //        /// </returns>
    //        /// <exception cref="InvalidOperationException">
    //        ///   This value's <see cref="ValueKind"/> is not <see cref="JsonValueKind.String"/>.
    //        /// </exception>
    //        /// <remarks>
    //        ///   This method is functionally equal to doing an ordinal comparison of the string produced by UTF-8 decoding
    //        ///   <paramref name="utf8Text" /> with the result of calling <see cref="GetString" />, but avoids creating the
    //        ///   string instances.
    //        /// </remarks>
    //        public bool ValueEquals(ReadOnlySpan<byte> utf8Text)
    //        {
    //            // CheckValidInstance is done in the helper

    //            if (TokenType == JsonTokenType.Null)
    //            {
    //                // This is different than Length == 0, in that it tests true for null, but false for ""
    //                return utf8Text == default;
    //            }

    //            return TextEqualsHelper(utf8Text, isPropertyName: false, shouldUnescape: true);
    //        }

    //        /// <summary>
    //        ///   Compares <paramref name="text" /> to the string value of this element.
    //        /// </summary>
    //        /// <param name="text">The text to compare against.</param>
    //        /// <returns>
    //        ///   <see langword="true" /> if the string value of this element matches <paramref name="text"/>,
    //        ///   <see langword="false" /> otherwise.
    //        /// </returns>
    //        /// <exception cref="InvalidOperationException">
    //        ///   This value's <see cref="ValueKind"/> is not <see cref="JsonValueKind.String"/>.
    //        /// </exception>
    //        /// <remarks>
    //        ///   This method is functionally equal to doing an ordinal comparison of <paramref name="text" /> and
    //        ///   the result of calling <see cref="GetString" />, but avoids creating the string instance.
    //        /// </remarks>
    //        public bool ValueEquals(ReadOnlySpan<char> text)
    //        {
    //            // CheckValidInstance is done in the helper

    //            if (TokenType == JsonTokenType.Null)
    //            {
    //                // This is different than Length == 0, in that it tests true for null, but false for ""
    //                return text == default;
    //            }

    //            return TextEqualsHelper(text, isPropertyName: false);
    //        }

    //        internal bool TextEqualsHelper(ReadOnlySpan<byte> utf8Text, bool isPropertyName, bool shouldUnescape)
    //        {
    //            CheckValidInstance();

    //            return _parent.TextEquals(_idx, utf8Text, isPropertyName, shouldUnescape);
    //        }

    //        internal bool TextEqualsHelper(ReadOnlySpan<char> text, bool isPropertyName)
    //        {
    //            CheckValidInstance();

    //            return _parent.TextEquals(_idx, text, isPropertyName);
    //        }

    //        ///// <summary>
    //        /////   Write the element into the provided writer as a JSON value.
    //        ///// </summary>
    //        ///// <param name="writer">The writer.</param>
    //        ///// <exception cref="ArgumentNullException">
    //        /////   The <paramref name="writer"/> parameter is <see langword="null"/>.
    //        ///// </exception>
    //        ///// <exception cref="InvalidOperationException">
    //        /////   This value's <see cref="ValueKind"/> is <see cref="JsonValueKind.Undefined"/>.
    //        ///// </exception>
    //        ///// <exception cref="ObjectDisposedException">
    //        /////   The parent <see cref="JsonDocument"/> has been disposed.
    //        ///// </exception>
    //        //public void WriteTo(Utf8JsonWriter writer)
    //        //{
    //        //    if (writer == null)
    //        //    {
    //        //        throw new ArgumentNullException(nameof(writer));
    //        //    }

    //        //    CheckValidInstance();

    //        //    _parent.WriteElementTo(_idx, writer);
    //        //}

    //        /// <summary>
    //        ///   Get an enumerator to enumerate the values in the JSON array represented by this JsonElement.
    //        /// </summary>
    //        /// <returns>
    //        ///   An enumerator to enumerate the values in the JSON array represented by this JsonElement.
    //        /// </returns>
    //        /// <exception cref="InvalidOperationException">
    //        ///   This value's <see cref="ValueKind"/> is not <see cref="JsonValueKind.Array"/>.
    //        /// </exception>
    //        /// <exception cref="ObjectDisposedException">
    //        ///   The parent <see cref="JsonDocument"/> has been disposed.
    //        /// </exception>
    //        public ArrayEnumerator EnumerateArray()
    //        {
    //            CheckValidInstance();

    //            JsonTokenType tokenType = TokenType;

    //            if (tokenType != JsonTokenType.StartArray)
    //            {
    //                //throw ThrowHelper.GetJsonElementWrongTypeException(JsonTokenType.StartArray, tokenType);
    //                throw new InvalidOperationException();
    //            }

    //            return new ArrayEnumerator(this);
    //        }


    //        /// <summary>
    //        ///   Get an enumerator to enumerate the properties in the JSON object represented by this JsonElement.
    //        /// </summary>
    //        /// <returns>
    //        ///   An enumerator to enumerate the properties in the JSON object represented by this JsonElement.
    //        /// </returns>
    //        /// <exception cref="InvalidOperationException">
    //        ///   This value's <see cref="ValueKind"/> is not <see cref="JsonValueKind.Object"/>.
    //        /// </exception>
    //        /// <exception cref="ObjectDisposedException">
    //        ///   The parent <see cref="JsonDocument"/> has been disposed.
    //        /// </exception>
    //        public ObjectEnumerator EnumerateObject()
    //        {
    //            CheckValidInstance();

    //            JsonTokenType tokenType = TokenType;

    //            if (tokenType != JsonTokenType.StartObject)
    //            {
    //                //throw ThrowHelper.GetJsonElementWrongTypeException(JsonTokenType.StartObject, tokenType);
    //                throw new InvalidOperationException();
    //            }

    //            return new ObjectEnumerator(this);
    //        }

    //        /// <summary>
    //        ///   Gets a string representation for the current value appropriate to the value type.
    //        /// </summary>
    //        /// <remarks>
    //        ///   <para>
    //        ///     For JsonElement built from <see cref="JsonDocument"/>:
    //        ///   </para>
    //        ///
    //        ///   <para>
    //        ///     For <see cref="JsonValueKind.Null"/>, <see cref="string.Empty"/> is returned.
    //        ///   </para>
    //        ///
    //        ///   <para>
    //        ///     For <see cref="JsonValueKind.True"/>, <see cref="bool.TrueString"/> is returned.
    //        ///   </para>
    //        ///
    //        ///   <para>
    //        ///     For <see cref="JsonValueKind.False"/>, <see cref="bool.FalseString"/> is returned.
    //        ///   </para>
    //        ///
    //        ///   <para>
    //        ///     For <see cref="JsonValueKind.String"/>, the value of <see cref="GetString"/>() is returned.
    //        ///   </para>
    //        ///
    //        ///   <para>
    //        ///     For other types, the value of <see cref="GetRawText"/>() is returned.
    //        ///   </para>
    //        /// </remarks>
    //        /// <returns>
    //        ///   A string representation for the current value appropriate to the value type.
    //        /// </returns>
    //        /// <exception cref="ObjectDisposedException">
    //        ///   The parent <see cref="JsonDocument"/> has been disposed.
    //        /// </exception>
    //        public override string? ToString()
    //        {
    //            switch (TokenType)
    //            {
    //                case JsonTokenType.None:
    //                case JsonTokenType.Null:
    //                    return string.Empty;
    //                case JsonTokenType.True:
    //                    return bool.TrueString;
    //                case JsonTokenType.False:
    //                    return bool.FalseString;
    //                case JsonTokenType.Number:
    //                case JsonTokenType.StartArray:
    //                case JsonTokenType.StartObject:
    //                    {
    //                        // null parent should have hit the None case
    //                        Debug.Assert(_parent != null);
    //                        return ((JwtPayloadDocument)_parent).GetRawValueAsString(_idx);
    //                    }
    //                case JsonTokenType.String:
    //                    return GetString();
    //                case JsonTokenType.Comment:
    //                case JsonTokenType.EndArray:
    //                case JsonTokenType.EndObject:
    //                default:
    //                    Debug.Fail($"No handler for {nameof(JsonTokenType)}.{TokenType}");
    //                    return string.Empty;
    //            }
    //        }

    //        /// <summary>
    //        ///   Get a JsonElement which can be safely stored beyond the lifetime of the
    //        ///   original <see cref="JsonDocument"/>.
    //        /// </summary>
    //        /// <returns>
    //        ///   A JsonElement which can be safely stored beyond the lifetime of the
    //        ///   original <see cref="JsonDocument"/>.
    //        /// </returns>
    //        /// <remarks>
    //        ///   <para>
    //        ///     If this JsonElement is itself the output of a previous call to Clone, or
    //        ///     a value contained within another JsonElement which was the output of a previous
    //        ///     call to Clone, this method results in no additional memory allocation.
    //        ///   </para>
    //        /// </remarks>
    //        public JwtElement Clone()
    //        {
    //            CheckValidInstance();

    //            if (!_parent.IsDisposable)
    //            {
    //                return this;
    //            }

    //            return _parent.CloneElement(_idx);
    //        }

    //        private void CheckValidInstance()
    //        {
    //            if (_parent == null)
    //            {
    //                throw new InvalidOperationException();
    //            }
    //        }

    //        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
    //        private string DebuggerDisplay => $"ValueKind = {ValueKind} : \"{ToString()}\"";

    //        internal static JsonValueKind ToValueKind(JsonTokenType tokenType)
    //        {
    //            switch (tokenType)
    //            {
    //                case JsonTokenType.None:
    //                    return JsonValueKind.Undefined;
    //                case JsonTokenType.StartArray:
    //                    return JsonValueKind.Array;
    //                case JsonTokenType.StartObject:
    //                    return JsonValueKind.Object;
    //                case JsonTokenType.String:
    //                case JsonTokenType.Number:
    //                case JsonTokenType.True:
    //                case JsonTokenType.False:
    //                case JsonTokenType.Null:
    //                    // This is the offset between the set of literals within JsonValueType and JsonTokenType
    //                    // Essentially: JsonTokenType.Null - JsonValueType.Null
    //                    return (JsonValueKind)((byte)tokenType - 4);
    //                default:
    //                    Debug.Fail($"No mapping for token type {tokenType}");
    //                    return JsonValueKind.Undefined;
    //            }
    //        }
    //    }

    //    internal static class JsonConstants
    //    {
    //        public const byte OpenBrace = (byte)'{';
    //        public const byte CloseBrace = (byte)'}';
    //        public const byte OpenBracket = (byte)'[';
    //        public const byte CloseBracket = (byte)']';
    //        public const byte Space = (byte)' ';
    //        public const byte CarriageReturn = (byte)'\r';
    //        public const byte LineFeed = (byte)'\n';
    //        public const byte Tab = (byte)'\t';
    //        public const byte ListSeparator = (byte)',';
    //        public const byte KeyValueSeperator = (byte)':';
    //        public const byte Quote = (byte)'"';
    //        public const byte BackSlash = (byte)'\\';
    //        public const byte Slash = (byte)'/';
    //        public const byte BackSpace = (byte)'\b';
    //        public const byte FormFeed = (byte)'\f';
    //        public const byte Asterisk = (byte)'*';
    //        public const byte Colon = (byte)':';
    //        public const byte Period = (byte)'.';
    //        public const byte Plus = (byte)'+';
    //        public const byte Hyphen = (byte)'-';
    //        public const byte UtcOffsetToken = (byte)'Z';
    //        public const byte TimePrefix = (byte)'T';

    //        public const int StackallocThreshold = 256;

    //        // In the worst case, an ASCII character represented as a single utf-8 byte could expand 6x when escaped.
    //        // For example: '+' becomes '\u0043'
    //        // Escaping surrogate pairs (represented by 3 or 4 utf-8 bytes) would expand to 12 bytes (which is still <= 6x).
    //        // The same factor applies to utf-16 characters.
    //        public const int MaxExpansionFactorWhileEscaping = 6;

    //        // In the worst case, a single UTF-16 character could be expanded to 3 UTF-8 bytes.
    //        // Only surrogate pairs expand to 4 UTF-8 bytes but that is a transformation of 2 UTF-16 characters goign to 4 UTF-8 bytes (factor of 2).
    //        // All other UTF-16 characters can be represented by either 1 or 2 UTF-8 bytes.
    //        public const int MaxExpansionFactorWhileTranscoding = 3;

    //        public static ReadOnlySpan<byte> NaNValue => new byte[] { (byte)'N', (byte)'a', (byte)'N' };
    //        public static ReadOnlySpan<byte> PositiveInfinityValue => new byte[] { (byte)'I', (byte)'n', (byte)'f', (byte)'i', (byte)'n', (byte)'i', (byte)'t', (byte)'y' };
    //        public static ReadOnlySpan<byte> NegativeInfinityValue => new byte[] { (byte)'-', (byte)'I', (byte)'n', (byte)'f', (byte)'i', (byte)'n', (byte)'i', (byte)'t', (byte)'y' };

    //        // Encoding Helpers
    //        public const char HighSurrogateStart = '\ud800';
    //        public const char HighSurrogateEnd = '\udbff';
    //        public const char LowSurrogateStart = '\udc00';
    //        public const char LowSurrogateEnd = '\udfff';

    //        public const int UnicodePlane01StartValue = 0x10000;
    //        public const int HighSurrogateStartValue = 0xD800;
    //        public const int HighSurrogateEndValue = 0xDBFF;
    //        public const int LowSurrogateStartValue = 0xDC00;
    //        public const int LowSurrogateEndValue = 0xDFFF;
    //        public const int BitShiftBy10 = 0x400;
    //    }


    //    internal static partial class JsonReaderHelper
    //    {
    //        public static string TranscodeHelper(ReadOnlySpan<byte> utf8Unescaped)
    //        {
    //            try
    //            {
    //                return Utf8.GetString(utf8Unescaped);
    //            }
    //            catch (DecoderFallbackException ex)
    //            {
    //                // We want to be consistent with the exception being thrown
    //                // so the user only has to catch a single exception.
    //                // Since we already throw InvalidOperationException for mismatch token type,
    //                // and while unescaping, using that exception for failure to decode invalid UTF-8 bytes as well.
    //                // Therefore, wrapping the DecoderFallbackException around an InvalidOperationException.
    //                //   throw ThrowHelper.GetInvalidOperationException_ReadInvalidUTF8(ex);
    //                throw new InvalidOperationException("Invalid UTF8", ex);
    //            }
    //        }


    //        public static (int, int) CountNewLines(ReadOnlySpan<byte> data)
    //        {
    //            int lastLineFeedIndex = -1;
    //            int newLines = 0;
    //            for (int i = 0; i < data.Length; i++)
    //            {
    //                if (data[i] == JsonConstants.LineFeed)
    //                {
    //                    lastLineFeedIndex = i;
    //                    newLines++;
    //                }
    //            }
    //            return (newLines, lastLineFeedIndex);
    //        }

    //        internal static JsonValueKind ToValueKind(this JsonTokenType tokenType)
    //        {
    //            switch (tokenType)
    //            {
    //                case JsonTokenType.None:
    //                    return JsonValueKind.Undefined;
    //                case JsonTokenType.StartArray:
    //                    return JsonValueKind.Array;
    //                case JsonTokenType.StartObject:
    //                    return JsonValueKind.Object;
    //                case JsonTokenType.String:
    //                case JsonTokenType.Number:
    //                case JsonTokenType.True:
    //                case JsonTokenType.False:
    //                case JsonTokenType.Null:
    //                    // This is the offset between the set of literals within JsonValueType and JsonTokenType
    //                    // Essentially: JsonTokenType.Null - JsonValueType.Null
    //                    return (JsonValueKind)((byte)tokenType - 4);
    //                default:
    //                    Debug.Fail($"No mapping for token type {tokenType}");
    //                    return JsonValueKind.Undefined;
    //            }
    //        }

    //        // Returns true if the TokenType is a primitive "value", i.e. String, Number, True, False, and Null
    //        // Otherwise, return false.
    //        public static bool IsTokenTypePrimitive(JsonTokenType tokenType) =>
    //            (tokenType - JsonTokenType.String) <= (JsonTokenType.Null - JsonTokenType.String);

    //        //// A hex digit is valid if it is in the range: [0..9] | [A..F] | [a..f]
    //        //// Otherwise, return false.
    //        //public static bool IsHexDigit(byte nextByte) => HexConverter.IsHexChar(nextByte);

    //        // https://tools.ietf.org/html/rfc8259
    //        // Does the span contain '"', '\',  or any control characters (i.e. 0 to 31)
    //        // IndexOfAny(34, 92, < 32)
    //        // Borrowed and modified from SpanHelpers.Byte:
    //        // https://github.com/dotnet/corefx/blob/fc169cddedb6820aaabbdb8b7bece2a3df0fd1a5/src/Common/src/CoreLib/System/SpanHelpers.Byte.cs#L473-L604
    //        [MethodImpl(MethodImplOptions.AggressiveInlining)]
    //        public static int IndexOfQuoteOrAnyControlOrBackSlash(this ReadOnlySpan<byte> span)
    //        {
    //            return IndexOfOrLessThan(
    //                    ref MemoryMarshal.GetReference(span),
    //                    JsonConstants.Quote,
    //                    JsonConstants.BackSlash,
    //                    lessThan: 32,   // Space ' '
    //                    span.Length);
    //        }

    //        private static unsafe int IndexOfOrLessThan(ref byte searchSpace, byte value0, byte value1, byte lessThan, int length)
    //        {
    //            Debug.Assert(length >= 0);

    //            uint uValue0 = value0; // Use uint for comparisons to avoid unnecessary 8->32 extensions
    //            uint uValue1 = value1; // Use uint for comparisons to avoid unnecessary 8->32 extensions
    //            uint uLessThan = lessThan; // Use uint for comparisons to avoid unnecessary 8->32 extensions
    //            IntPtr index = (IntPtr)0; // Use IntPtr for arithmetic to avoid unnecessary 64->32->64 truncations
    //            IntPtr nLength = (IntPtr)length;

    //            if (Vector.IsHardwareAccelerated && length >= Vector<byte>.Count * 2)
    //            {
    //                int unaligned = (int)Unsafe.AsPointer(ref searchSpace) & (Vector<byte>.Count - 1);
    //                nLength = (IntPtr)((Vector<byte>.Count - unaligned) & (Vector<byte>.Count - 1));
    //            }
    //        SequentialScan:
    //            uint lookUp;
    //            while ((byte*)nLength >= (byte*)8)
    //            {
    //                nLength -= 8;

    //                lookUp = Unsafe.AddByteOffset(ref searchSpace, index);
    //                if (uValue0 == lookUp || uValue1 == lookUp || uLessThan > lookUp)
    //                    goto Found;
    //                lookUp = Unsafe.AddByteOffset(ref searchSpace, index + 1);
    //                if (uValue0 == lookUp || uValue1 == lookUp || uLessThan > lookUp)
    //                    goto Found1;
    //                lookUp = Unsafe.AddByteOffset(ref searchSpace, index + 2);
    //                if (uValue0 == lookUp || uValue1 == lookUp || uLessThan > lookUp)
    //                    goto Found2;
    //                lookUp = Unsafe.AddByteOffset(ref searchSpace, index + 3);
    //                if (uValue0 == lookUp || uValue1 == lookUp || uLessThan > lookUp)
    //                    goto Found3;
    //                lookUp = Unsafe.AddByteOffset(ref searchSpace, index + 4);
    //                if (uValue0 == lookUp || uValue1 == lookUp || uLessThan > lookUp)
    //                    goto Found4;
    //                lookUp = Unsafe.AddByteOffset(ref searchSpace, index + 5);
    //                if (uValue0 == lookUp || uValue1 == lookUp || uLessThan > lookUp)
    //                    goto Found5;
    //                lookUp = Unsafe.AddByteOffset(ref searchSpace, index + 6);
    //                if (uValue0 == lookUp || uValue1 == lookUp || uLessThan > lookUp)
    //                    goto Found6;
    //                lookUp = Unsafe.AddByteOffset(ref searchSpace, index + 7);
    //                if (uValue0 == lookUp || uValue1 == lookUp || uLessThan > lookUp)
    //                    goto Found7;

    //                index += 8;
    //            }

    //            if ((byte*)nLength >= (byte*)4)
    //            {
    //                nLength -= 4;

    //                lookUp = Unsafe.AddByteOffset(ref searchSpace, index);
    //                if (uValue0 == lookUp || uValue1 == lookUp || uLessThan > lookUp)
    //                    goto Found;
    //                lookUp = Unsafe.AddByteOffset(ref searchSpace, index + 1);
    //                if (uValue0 == lookUp || uValue1 == lookUp || uLessThan > lookUp)
    //                    goto Found1;
    //                lookUp = Unsafe.AddByteOffset(ref searchSpace, index + 2);
    //                if (uValue0 == lookUp || uValue1 == lookUp || uLessThan > lookUp)
    //                    goto Found2;
    //                lookUp = Unsafe.AddByteOffset(ref searchSpace, index + 3);
    //                if (uValue0 == lookUp || uValue1 == lookUp || uLessThan > lookUp)
    //                    goto Found3;

    //                index += 4;
    //            }

    //            while ((byte*)nLength > (byte*)0)
    //            {
    //                nLength -= 1;

    //                lookUp = Unsafe.AddByteOffset(ref searchSpace, index);
    //                if (uValue0 == lookUp || uValue1 == lookUp || uLessThan > lookUp)
    //                    goto Found;

    //                index += 1;
    //            }

    //            if (Vector.IsHardwareAccelerated && ((int)(byte*)index < length))
    //            {
    //                nLength = (IntPtr)((length - (int)(byte*)index) & ~(Vector<byte>.Count - 1));

    //                // Get comparison Vector
    //                Vector<byte> values0 = new Vector<byte>(value0);
    //                Vector<byte> values1 = new Vector<byte>(value1);
    //                Vector<byte> valuesLessThan = new Vector<byte>(lessThan);

    //                while ((byte*)nLength > (byte*)index)
    //                {
    //                    Vector<byte> vData = Unsafe.ReadUnaligned<Vector<byte>>(ref Unsafe.AddByteOffset(ref searchSpace, index));

    //                    var vMatches = Vector.BitwiseOr(
    //                                    Vector.BitwiseOr(
    //                                        Vector.Equals(vData, values0),
    //                                        Vector.Equals(vData, values1)),
    //                                    Vector.LessThan(vData, valuesLessThan));

    //                    if (Vector<byte>.Zero.Equals(vMatches))
    //                    {
    //                        index += Vector<byte>.Count;
    //                        continue;
    //                    }
    //                    // Find offset of first match
    //                    return (int)(byte*)index + LocateFirstFoundByte(vMatches);
    //                }

    //                if ((int)(byte*)index < length)
    //                {
    //                    nLength = (IntPtr)(length - (int)(byte*)index);
    //                    goto SequentialScan;
    //                }
    //            }
    //            return -1;
    //        Found: // Workaround for https://github.com/dotnet/runtime/issues/8795
    //            return (int)(byte*)index;
    //        Found1:
    //            return (int)(byte*)(index + 1);
    //        Found2:
    //            return (int)(byte*)(index + 2);
    //        Found3:
    //            return (int)(byte*)(index + 3);
    //        Found4:
    //            return (int)(byte*)(index + 4);
    //        Found5:
    //            return (int)(byte*)(index + 5);
    //        Found6:
    //            return (int)(byte*)(index + 6);
    //        Found7:
    //            return (int)(byte*)(index + 7);
    //        }

    //        // Vector sub-search adapted from https://github.com/aspnet/KestrelHttpServer/pull/1138
    //        [MethodImpl(MethodImplOptions.AggressiveInlining)]
    //        private static int LocateFirstFoundByte(Vector<byte> match)
    //        {
    //            var vector64 = Vector.AsVectorUInt64(match);
    //            ulong candidate = 0;
    //            int i = 0;
    //            // Pattern unrolled by jit https://github.com/dotnet/coreclr/pull/8001
    //            for (; i < Vector<ulong>.Count; i++)
    //            {
    //                candidate = vector64[i];
    //                if (candidate != 0)
    //                {
    //                    break;
    //                }
    //            }

    //            // Single LEA instruction with jitted const (using function result)
    //            return i * 8 + LocateFirstFoundByte(candidate);
    //        }

    //        [MethodImpl(MethodImplOptions.AggressiveInlining)]
    //        private static int LocateFirstFoundByte(ulong match)
    //        {
    //            // Flag least significant power of two bit
    //            var powerOfTwoFlag = match ^ (match - 1);
    //            // Shift all powers of two into the high byte and extract
    //            return (int)((powerOfTwoFlag * XorPowerOfTwoToHighByte) >> 57);
    //        }

    //        private const ulong XorPowerOfTwoToHighByte = (0x07ul |
    //                                               0x06ul << 8 |
    //                                               0x05ul << 16 |
    //                                               0x04ul << 24 |
    //                                               0x03ul << 32 |
    //                                               0x02ul << 40 |
    //                                               0x01ul << 48) + 1;

    //        public static bool TryGetFloatingPointConstant(ReadOnlySpan<byte> span, out double value)
    //        {
    //            if (span.Length == 3)
    //            {
    //                if (span.SequenceEqual(JsonConstants.NaNValue))
    //                {
    //                    value = double.NaN;
    //                    return true;
    //                }
    //            }
    //            else if (span.Length == 8)
    //            {
    //                if (span.SequenceEqual(JsonConstants.PositiveInfinityValue))
    //                {
    //                    value = double.PositiveInfinity;
    //                    return true;
    //                }
    //            }
    //            else if (span.Length == 9)
    //            {
    //                if (span.SequenceEqual(JsonConstants.NegativeInfinityValue))
    //                {
    //                    value = double.NegativeInfinity;
    //                    return true;
    //                }
    //            }

    //            value = 0;
    //            return false;
    //        }

    //        internal static int GetUtf8FromText(ReadOnlySpan<char> text, Span<byte> dest)
    //        {
    //            try
    //            {
    //                return Utf8.GetBytes(text, dest);
    //            }
    //            catch (EncoderFallbackException ex)
    //            {
    //                // We want to be consistent with the exception being thrown
    //                // so the user only has to catch a single exception.
    //                // Since we already throw ArgumentException when validating other arguments,
    //                // using that exception for failure to encode invalid UTF-16 chars as well.
    //                // Therefore, wrapping the EncoderFallbackException around an ArgumentException.
    //                //throw  ThrowHelper.GetArgumentException_ReadInvalidUTF16(ex);
    //                throw new InvalidOperationException("Invalid UTF16", ex);
    //            }
    //        }
    //        internal static void Unescape(ReadOnlySpan<byte> source, Span<byte> destination, int idx, out int written)
    //        {
    //            Debug.Assert(idx >= 0 && idx < source.Length);
    //            Debug.Assert(source[idx] == JsonConstants.BackSlash);
    //            Debug.Assert(destination.Length >= source.Length);

    //            source.Slice(0, idx).CopyTo(destination);
    //            written = idx;

    //            for (; idx < source.Length; idx++)
    //            {
    //                byte currentByte = source[idx];
    //                if (currentByte == JsonConstants.BackSlash)
    //                {
    //                    idx++;
    //                    currentByte = source[idx];

    //                    if (currentByte == JsonConstants.Quote)
    //                    {
    //                        destination[written++] = JsonConstants.Quote;
    //                    }
    //                    else if (currentByte == 'n')
    //                    {
    //                        destination[written++] = JsonConstants.LineFeed;
    //                    }
    //                    else if (currentByte == 'r')
    //                    {
    //                        destination[written++] = JsonConstants.CarriageReturn;
    //                    }
    //                    else if (currentByte == JsonConstants.BackSlash)
    //                    {
    //                        destination[written++] = JsonConstants.BackSlash;
    //                    }
    //                    else if (currentByte == JsonConstants.Slash)
    //                    {
    //                        destination[written++] = JsonConstants.Slash;
    //                    }
    //                    else if (currentByte == 't')
    //                    {
    //                        destination[written++] = JsonConstants.Tab;
    //                    }
    //                    else if (currentByte == 'b')
    //                    {
    //                        destination[written++] = JsonConstants.BackSpace;
    //                    }
    //                    else if (currentByte == 'f')
    //                    {
    //                        destination[written++] = JsonConstants.FormFeed;
    //                    }
    //                    else if (currentByte == 'u')
    //                    {
    //                        // The source is known to be valid JSON, and hence if we see a \u, it is guaranteed to have 4 hex digits following it
    //                        // Otherwise, the Utf8JsonReader would have alreayd thrown an exception.
    //                        Debug.Assert(source.Length >= idx + 5);

    //                        bool result = Utf8Parser.TryParse(source.Slice(idx + 1, 4), out int scalar, out int bytesConsumed, 'x');
    //                        Debug.Assert(result);
    //                        Debug.Assert(bytesConsumed == 4);
    //                        idx += bytesConsumed;     // The loop iteration will increment idx past the last hex digit

    //                        if (IsInRangeInclusive((uint)scalar, JsonConstants.HighSurrogateStartValue, JsonConstants.LowSurrogateEndValue))
    //                        {
    //                            // The first hex value cannot be a low surrogate.
    //                            if (scalar >= JsonConstants.LowSurrogateStartValue)
    //                            {
    //                                //ThrowHelper.ThrowInvalidOperationException_ReadInvalidUTF16(scalar);
    //                                throw new InvalidOperationException("Invalid UTF16");

    //                            }

    //                            Debug.Assert(IsInRangeInclusive((uint)scalar, JsonConstants.HighSurrogateStartValue, JsonConstants.HighSurrogateEndValue));

    //                            idx += 3;   // Skip the last hex digit and the next \u

    //                            // We must have a low surrogate following a high surrogate.
    //                            if (source.Length < idx + 4 || source[idx - 2] != '\\' || source[idx - 1] != 'u')
    //                            {
    //                                throw new InvalidOperationException("Invalid UTF16");
    //                                //ThrowHelper.ThrowInvalidOperationException_ReadInvalidUTF16();
    //                            }

    //                            // The source is known to be valid JSON, and hence if we see a \u, it is guaranteed to have 4 hex digits following it
    //                            // Otherwise, the Utf8JsonReader would have alreayd thrown an exception.
    //                            result = Utf8Parser.TryParse(source.Slice(idx, 4), out int lowSurrogate, out bytesConsumed, 'x');
    //                            Debug.Assert(result);
    //                            Debug.Assert(bytesConsumed == 4);

    //                            // If the first hex value is a high surrogate, the next one must be a low surrogate.
    //                            if (!IsInRangeInclusive((uint)lowSurrogate, JsonConstants.LowSurrogateStartValue, JsonConstants.LowSurrogateEndValue))
    //                            {
    //                                //ThrowHelper.ThrowInvalidOperationException_ReadInvalidUTF16(lowSurrogate);
    //                                throw new InvalidOperationException("Invalid UTF16");
    //                            }

    //                            idx += bytesConsumed - 1;  // The loop iteration will increment idx past the last hex digit

    //                            // To find the unicode scalar:
    //                            // (0x400 * (High surrogate - 0xD800)) + Low surrogate - 0xDC00 + 0x10000
    //                            scalar = (JsonConstants.BitShiftBy10 * (scalar - JsonConstants.HighSurrogateStartValue))
    //                                + (lowSurrogate - JsonConstants.LowSurrogateStartValue)
    //                                + JsonConstants.UnicodePlane01StartValue;
    //                        }

    //#if SUPPORT_SIMD
    //                        var rune = new Rune(scalar);
    //                        int bytesWritten = rune.EncodeToUtf8(destination.Slice(written));
    //#else
    //                        EncodeToUtf8Bytes((uint)scalar, destination.Slice(written), out int bytesWritten);
    //#endif
    //                        Debug.Assert(bytesWritten <= 4);
    //                        written += bytesWritten;
    //                    }
    //                }
    //                else
    //                {
    //                    destination[written++] = currentByte;
    //                }
    //            }
    //        }

    //        /// <summary>
    //        /// Returns <see langword="true"/> if <paramref name="value"/> is between
    //        /// <paramref name="lowerBound"/> and <paramref name="upperBound"/>, inclusive.
    //        /// </summary>
    //        [MethodImpl(MethodImplOptions.AggressiveInlining)]
    //        public static bool IsInRangeInclusive(uint value, uint lowerBound, uint upperBound)
    //            => (value - lowerBound) <= (upperBound - lowerBound);

    //        /// <summary>
    //        /// Returns <see langword="true"/> if <paramref name="value"/> is between
    //        /// <paramref name="lowerBound"/> and <paramref name="upperBound"/>, inclusive.
    //        /// </summary>
    //        [MethodImpl(MethodImplOptions.AggressiveInlining)]
    //        public static bool IsInRangeInclusive(int value, int lowerBound, int upperBound)
    //            => (uint)(value - lowerBound) <= (uint)(upperBound - lowerBound);

    //        /// <summary>
    //        /// Returns <see langword="true"/> if <paramref name="value"/> is between
    //        /// <paramref name="lowerBound"/> and <paramref name="upperBound"/>, inclusive.
    //        /// </summary>
    //        [MethodImpl(MethodImplOptions.AggressiveInlining)]
    //        public static bool IsInRangeInclusive(long value, long lowerBound, long upperBound)
    //            => (ulong)(value - lowerBound) <= (ulong)(upperBound - lowerBound);

    //        /// <summary>
    //        /// Returns <see langword="true"/> if <paramref name="value"/> is between
    //        /// <paramref name="lowerBound"/> and <paramref name="upperBound"/>, inclusive.
    //        /// </summary>
    //        [MethodImpl(MethodImplOptions.AggressiveInlining)]
    //        public static bool IsInRangeInclusive(JsonTokenType value, JsonTokenType lowerBound, JsonTokenType upperBound)
    //            => (value - lowerBound) <= (upperBound - lowerBound);

    //        public static bool UnescapeAndCompare(ReadOnlySpan<byte> utf8Source, ReadOnlySpan<byte> other)
    //        {
    //            Debug.Assert(utf8Source.Length >= other.Length && utf8Source.Length / JsonConstants.MaxExpansionFactorWhileEscaping <= other.Length);

    //            byte[]? unescapedArray = null;

    //            Span<byte> utf8Unescaped = utf8Source.Length <= JsonConstants.StackallocThreshold ?
    //                stackalloc byte[utf8Source.Length] :
    //                (unescapedArray = ArrayPool<byte>.Shared.Rent(utf8Source.Length));

    //            Unescape(utf8Source, utf8Unescaped, 0, out int written);
    //            Debug.Assert(written > 0);

    //            utf8Unescaped = utf8Unescaped.Slice(0, written);
    //            Debug.Assert(!utf8Unescaped.IsEmpty);

    //            bool result = other.SequenceEqual(utf8Unescaped);

    //            if (unescapedArray != null)
    //            {
    //                utf8Unescaped.Clear();
    //                ArrayPool<byte>.Shared.Return(unescapedArray);
    //            }

    //            return result;
    //        }

    //        // TODO: Similar to escaping, replace the unescaping logic with publicly shipping APIs from https://github.com/dotnet/runtime/issues/27919
    //        public static string GetUnescapedString(ReadOnlySpan<byte> utf8Source, int idx)
    //        {
    //            // The escaped name is always >= than the unescaped, so it is safe to use escaped name for the buffer length.
    //            int length = utf8Source.Length;
    //            byte[]? pooledName = null;

    //            Span<byte> utf8Unescaped = length <= JsonConstants.StackallocThreshold ?
    //                stackalloc byte[length] :
    //                (pooledName = ArrayPool<byte>.Shared.Rent(length));

    //            Unescape(utf8Source, utf8Unescaped, idx, out int written);
    //            Debug.Assert(written > 0);

    //            utf8Unescaped = utf8Unescaped.Slice(0, written);
    //            Debug.Assert(!utf8Unescaped.IsEmpty);

    //            string utf8String = TranscodeHelper(utf8Unescaped);

    //            if (pooledName != null)
    //            {
    //                utf8Unescaped.Clear();
    //                ArrayPool<byte>.Shared.Return(pooledName);
    //            }

    //            return utf8String;
    //        }

    //#if !SUPPORT_SIMD
    //        /// <summary>
    //        /// Copies the UTF-8 code unit representation of this scalar to an output buffer.
    //        /// The buffer must be large enough to hold the required number of <see cref="byte"/>s.
    //        /// </summary>
    //        private static void EncodeToUtf8Bytes(uint scalar, Span<byte> utf8Destination, out int bytesWritten)
    //        {
    //            Debug.Assert(IsValidUnicodeScalar(scalar));
    //            Debug.Assert(utf8Destination.Length >= 4);

    //            if (scalar < 0x80U)
    //            {
    //                // Single UTF-8 code unit
    //                utf8Destination[0] = (byte)scalar;
    //                bytesWritten = 1;
    //            }
    //            else if (scalar < 0x800U)
    //            {
    //                // Two UTF-8 code units
    //                utf8Destination[0] = (byte)(0xC0U | (scalar >> 6));
    //                utf8Destination[1] = (byte)(0x80U | (scalar & 0x3FU));
    //                bytesWritten = 2;
    //            }
    //            else if (scalar < 0x10000U)
    //            {
    //                // Three UTF-8 code units
    //                utf8Destination[0] = (byte)(0xE0U | (scalar >> 12));
    //                utf8Destination[1] = (byte)(0x80U | ((scalar >> 6) & 0x3FU));
    //                utf8Destination[2] = (byte)(0x80U | (scalar & 0x3FU));
    //                bytesWritten = 3;
    //            }
    //            else
    //            {
    //                // Four UTF-8 code units
    //                utf8Destination[0] = (byte)(0xF0U | (scalar >> 18));
    //                utf8Destination[1] = (byte)(0x80U | ((scalar >> 12) & 0x3FU));
    //                utf8Destination[2] = (byte)(0x80U | ((scalar >> 6) & 0x3FU));
    //                utf8Destination[3] = (byte)(0x80U | (scalar & 0x3FU));
    //                bytesWritten = 4;
    //            }
    //        }

    //        /// <summary>
    //        /// Returns <see langword="true"/> if <paramref name="value"/> is a valid Unicode scalar
    //        /// value, i.e., is in [ U+0000..U+D7FF ], inclusive; or [ U+E000..U+10FFFF ], inclusive.
    //        /// </summary>
    //        [MethodImpl(MethodImplOptions.AggressiveInlining)]
    //        public static bool IsValidUnicodeScalar(uint value)
    //        {
    //            // By XORing the incoming value with 0xD800, surrogate code points
    //            // are moved to the range [ U+0000..U+07FF ], and all valid scalar
    //            // values are clustered into the single range [ U+0800..U+10FFFF ],
    //            // which allows performing a single fast range check.

    //            return IsInRangeInclusive(value ^ 0xD800U, 0x800U, 0x10FFFFU);
    //        }
    //#endif

    //        // TODO: Replace this with publicly shipping implementation: https://github.com/dotnet/runtime/issues/28204
    //        /// <summary>
    //        /// Converts a span containing a sequence of UTF-16 bytes into UTF-8 bytes.
    //        ///
    //        /// This method will consume as many of the input bytes as possible.
    //        ///
    //        /// On successful exit, the entire input was consumed and encoded successfully. In this case, <paramref name="bytesConsumed"/> will be
    //        /// equal to the length of the <paramref name="utf16Source"/> and <paramref name="bytesWritten"/> will equal the total number of bytes written to
    //        /// the <paramref name="utf8Destination"/>.
    //        /// </summary>
    //        /// <param name="utf16Source">A span containing a sequence of UTF-16 bytes.</param>
    //        /// <param name="utf8Destination">A span to write the UTF-8 bytes into.</param>
    //        /// <param name="bytesConsumed">On exit, contains the number of bytes that were consumed from the <paramref name="utf16Source"/>.</param>
    //        /// <param name="bytesWritten">On exit, contains the number of bytes written to <paramref name="utf8Destination"/></param>
    //        /// <returns>A <see cref="OperationStatus"/> value representing the state of the conversion.</returns>
    //        public static unsafe OperationStatus ToUtf8(ReadOnlySpan<byte> utf16Source, Span<byte> utf8Destination, out int bytesConsumed, out int bytesWritten)
    //        {
    //            //
    //            //
    //            // KEEP THIS IMPLEMENTATION IN SYNC WITH https://github.com/dotnet/coreclr/blob/master/src/System.Private.CoreLib/shared/System/Text/UTF8Encoding.cs#L841
    //            //
    //            //
    //            fixed (byte* chars = &MemoryMarshal.GetReference(utf16Source))
    //            fixed (byte* bytes = &MemoryMarshal.GetReference(utf8Destination))
    //            {
    //                char* pSrc = (char*)chars;
    //                byte* pTarget = bytes;

    //                char* pEnd = (char*)(chars + utf16Source.Length);
    //                byte* pAllocatedBufferEnd = pTarget + utf8Destination.Length;

    //                // assume that JIT will enregister pSrc, pTarget and ch

    //                // Entering the fast encoding loop incurs some overhead that does not get amortized for small
    //                // number of characters, and the slow encoding loop typically ends up running for the last few
    //                // characters anyway since the fast encoding loop needs 5 characters on input at least.
    //                // Thus don't use the fast decoding loop at all if we don't have enough characters. The threashold
    //                // was choosen based on performance testing.
    //                // Note that if we don't have enough bytes, pStop will prevent us from entering the fast loop.
    //                while (pEnd - pSrc > 13)
    //                {
    //                    // we need at least 1 byte per character, but Convert might allow us to convert
    //                    // only part of the input, so try as much as we can.  Reduce charCount if necessary
    //                    int available = Math.Min(PtrDiff(pEnd, pSrc), PtrDiff(pAllocatedBufferEnd, pTarget));

    //                    // FASTLOOP:
    //                    // - optimistic range checks
    //                    // - fallbacks to the slow loop for all special cases, exception throwing, etc.

    //                    // To compute the upper bound, assume that all characters are ASCII characters at this point,
    //                    //  the boundary will be decreased for every non-ASCII character we encounter
    //                    // Also, we need 5 chars reserve for the unrolled ansi decoding loop and for decoding of surrogates
    //                    // If there aren't enough bytes for the output, then pStop will be <= pSrc and will bypass the loop.
    //                    char* pStop = pSrc + available - 5;
    //                    if (pSrc >= pStop)
    //                        break;

    //                    do
    //                    {
    //                        int ch = *pSrc;
    //                        pSrc++;

    //                        if (ch > 0x7F)
    //                        {
    //                            goto LongCode;
    //                        }
    //                        *pTarget = (byte)ch;
    //                        pTarget++;

    //                        // get pSrc aligned
    //                        if ((unchecked((int)pSrc) & 0x2) != 0)
    //                        {
    //                            ch = *pSrc;
    //                            pSrc++;
    //                            if (ch > 0x7F)
    //                            {
    //                                goto LongCode;
    //                            }
    //                            *pTarget = (byte)ch;
    //                            pTarget++;
    //                        }

    //                        // Run 4 characters at a time!
    //                        while (pSrc < pStop)
    //                        {
    //                            ch = *(int*)pSrc;
    //                            int chc = *(int*)(pSrc + 2);
    //                            if (((ch | chc) & unchecked((int)0xFF80FF80)) != 0)
    //                            {
    //                                goto LongCodeWithMask;
    //                            }

    //                            // Unfortunately, this is endianess sensitive
    //#if BIGENDIAN
    //                            *pTarget = (byte)(ch >> 16);
    //                            *(pTarget + 1) = (byte)ch;
    //                            pSrc += 4;
    //                            *(pTarget + 2) = (byte)(chc >> 16);
    //                            *(pTarget + 3) = (byte)chc;
    //                            pTarget += 4;
    //#else // BIGENDIAN
    //                            *pTarget = (byte)ch;
    //                            *(pTarget + 1) = (byte)(ch >> 16);
    //                            pSrc += 4;
    //                            *(pTarget + 2) = (byte)chc;
    //                            *(pTarget + 3) = (byte)(chc >> 16);
    //                            pTarget += 4;
    //#endif // BIGENDIAN
    //                        }
    //                        continue;

    //                    LongCodeWithMask:
    //#if BIGENDIAN
    //                        // be careful about the sign extension
    //                        ch = (int)(((uint)ch) >> 16);
    //#else // BIGENDIAN
    //                        ch = (char)ch;
    //#endif // BIGENDIAN
    //                        pSrc++;

    //                        if (ch > 0x7F)
    //                        {
    //                            goto LongCode;
    //                        }
    //                        *pTarget = (byte)ch;
    //                        pTarget++;
    //                        continue;

    //                    LongCode:
    //                        // use separate helper variables for slow and fast loop so that the jit optimizations
    //                        // won't get confused about the variable lifetimes
    //                        int chd;
    //                        if (ch <= 0x7FF)
    //                        {
    //                            // 2 byte encoding
    //                            chd = unchecked((sbyte)0xC0) | (ch >> 6);
    //                        }
    //                        else
    //                        {
    //                            // if (!IsLowSurrogate(ch) && !IsHighSurrogate(ch))
    //                            if (!IsInRangeInclusive(ch, JsonConstants.HighSurrogateStart, JsonConstants.LowSurrogateEnd))
    //                            {
    //                                // 3 byte encoding
    //                                chd = unchecked((sbyte)0xE0) | (ch >> 12);
    //                            }
    //                            else
    //                            {
    //                                // 4 byte encoding - high surrogate + low surrogate
    //                                // if (!IsHighSurrogate(ch))
    //                                if (ch > JsonConstants.HighSurrogateEnd)
    //                                {
    //                                    // low without high -> bad
    //                                    goto InvalidData;
    //                                }

    //                                chd = *pSrc;

    //                                // if (!IsLowSurrogate(chd)) {
    //                                if (!IsInRangeInclusive(chd, JsonConstants.LowSurrogateStart, JsonConstants.LowSurrogateEnd))
    //                                {
    //                                    // high not followed by low -> bad
    //                                    goto InvalidData;
    //                                }

    //                                pSrc++;

    //                                ch = chd + (ch << 10) +
    //                                    (0x10000
    //                                    - JsonConstants.LowSurrogateStart
    //                                    - (JsonConstants.HighSurrogateStart << 10));

    //                                *pTarget = (byte)(unchecked((sbyte)0xF0) | (ch >> 18));
    //                                // pStop - this byte is compensated by the second surrogate character
    //                                // 2 input chars require 4 output bytes.  2 have been anticipated already
    //                                // and 2 more will be accounted for by the 2 pStop-- calls below.
    //                                pTarget++;

    //                                chd = unchecked((sbyte)0x80) | (ch >> 12) & 0x3F;
    //                            }
    //                            *pTarget = (byte)chd;
    //                            pStop--;                    // 3 byte sequence for 1 char, so need pStop-- and the one below too.
    //                            pTarget++;

    //                            chd = unchecked((sbyte)0x80) | (ch >> 6) & 0x3F;
    //                        }
    //                        *pTarget = (byte)chd;
    //                        pStop--;                        // 2 byte sequence for 1 char so need pStop--.

    //                        *(pTarget + 1) = (byte)(unchecked((sbyte)0x80) | ch & 0x3F);
    //                        // pStop - this byte is already included

    //                        pTarget += 2;
    //                    }
    //                    while (pSrc < pStop);

    //                    Debug.Assert(pTarget <= pAllocatedBufferEnd, "[UTF8Encoding.GetBytes]pTarget <= pAllocatedBufferEnd");
    //                }

    //                while (pSrc < pEnd)
    //                {
    //                    // SLOWLOOP: does all range checks, handles all special cases, but it is slow

    //                    // read next char. The JIT optimization seems to be getting confused when
    //                    // compiling "ch = *pSrc++;", so rather use "ch = *pSrc; pSrc++;" instead
    //                    int ch = *pSrc;
    //                    pSrc++;

    //                    if (ch <= 0x7F)
    //                    {
    //                        if (pAllocatedBufferEnd - pTarget <= 0)
    //                            goto DestinationFull;

    //                        *pTarget = (byte)ch;
    //                        pTarget++;
    //                        continue;
    //                    }

    //                    int chd;
    //                    if (ch <= 0x7FF)
    //                    {
    //                        if (pAllocatedBufferEnd - pTarget <= 1)
    //                            goto DestinationFull;

    //                        // 2 byte encoding
    //                        chd = unchecked((sbyte)0xC0) | (ch >> 6);
    //                    }
    //                    else
    //                    {
    //                        // if (!IsLowSurrogate(ch) && !IsHighSurrogate(ch))
    //                        if (!IsInRangeInclusive(ch, JsonConstants.HighSurrogateStart, JsonConstants.LowSurrogateEnd))
    //                        {
    //                            if (pAllocatedBufferEnd - pTarget <= 2)
    //                                goto DestinationFull;

    //                            // 3 byte encoding
    //                            chd = unchecked((sbyte)0xE0) | (ch >> 12);
    //                        }
    //                        else
    //                        {
    //                            if (pAllocatedBufferEnd - pTarget <= 3)
    //                                goto DestinationFull;

    //                            // 4 byte encoding - high surrogate + low surrogate
    //                            // if (!IsHighSurrogate(ch))
    //                            if (ch > JsonConstants.HighSurrogateEnd)
    //                            {
    //                                // low without high -> bad
    //                                goto InvalidData;
    //                            }

    //                            if (pSrc >= pEnd)
    //                                goto NeedMoreData;

    //                            chd = *pSrc;

    //                            // if (!IsLowSurrogate(chd)) {
    //                            if (!IsInRangeInclusive(chd, JsonConstants.LowSurrogateStart, JsonConstants.LowSurrogateEnd))
    //                            {
    //                                // high not followed by low -> bad
    //                                goto InvalidData;
    //                            }

    //                            pSrc++;

    //                            ch = chd + (ch << 10) +
    //                                (0x10000
    //                                - JsonConstants.LowSurrogateStart
    //                                - (JsonConstants.HighSurrogateStart << 10));

    //                            *pTarget = (byte)(unchecked((sbyte)0xF0) | (ch >> 18));
    //                            pTarget++;

    //                            chd = unchecked((sbyte)0x80) | (ch >> 12) & 0x3F;
    //                        }
    //                        *pTarget = (byte)chd;
    //                        pTarget++;

    //                        chd = unchecked((sbyte)0x80) | (ch >> 6) & 0x3F;
    //                    }

    //                    *pTarget = (byte)chd;
    //                    *(pTarget + 1) = (byte)(unchecked((sbyte)0x80) | ch & 0x3F);

    //                    pTarget += 2;
    //                }

    //                bytesConsumed = (int)((byte*)pSrc - chars);
    //                bytesWritten = (int)(pTarget - bytes);
    //                return OperationStatus.Done;

    //            InvalidData:
    //                bytesConsumed = (int)((byte*)(pSrc - 1) - chars);
    //                bytesWritten = (int)(pTarget - bytes);
    //                return OperationStatus.InvalidData;

    //            DestinationFull:
    //                bytesConsumed = (int)((byte*)(pSrc - 1) - chars);
    //                bytesWritten = (int)(pTarget - bytes);
    //                return OperationStatus.DestinationTooSmall;

    //            NeedMoreData:
    //                bytesConsumed = (int)((byte*)(pSrc - 1) - chars);
    //                bytesWritten = (int)(pTarget - bytes);
    //                return OperationStatus.NeedMoreData;
    //            }
    //        }

    //        [MethodImpl(MethodImplOptions.AggressiveInlining)]
    //        private static unsafe int PtrDiff(char* a, char* b)
    //        {
    //            return (int)(((uint)((byte*)a - (byte*)b)) >> 1);
    //        }

    //        // byte* flavor just for parity
    //        [MethodImpl(MethodImplOptions.AggressiveInlining)]
    //        private static unsafe int PtrDiff(byte* a, byte* b)
    //        {
    //            return (int)(a - b);
    //        }
    //    }

    //    public partial struct JwtElement
    //    {
    //        /// <summary>
    //        ///   An enumerable and enumerator for the properties of a JSON object.
    //        /// </summary>
    //        [DebuggerDisplay("{Current,nq}")]
    //        public struct ObjectEnumerator : IEnumerable<JwtProperty2>, IEnumerator<JwtProperty2>
    //        {
    //            private readonly JwtElement _target;
    //            private int _curIdx;
    //            private readonly int _endIdxOrVersion;

    //            internal ObjectEnumerator(JwtElement target)
    //            {
    //                _target = target;
    //                _curIdx = -1;

    //                Debug.Assert(target.TokenType == JsonTokenType.StartObject);
    //                _endIdxOrVersion = target._parent.GetEndIndex(_target._idx, includeEndElement: false);
    //            }

    //            /// <inheritdoc />
    //            public JwtProperty2 Current
    //            {
    //                get
    //                {
    //                    if (_curIdx < 0)
    //                    {
    //                        return default;
    //                    }

    //                    return new JwtProperty2(new JwtElement(_target._parent, _curIdx));
    //                }
    //            }

    //            /// <summary>
    //            ///   Returns an enumerator that iterates the properties of an object.
    //            /// </summary>
    //            /// <returns>
    //            ///   An <see cref="ObjectEnumerator"/> value that can be used to iterate
    //            ///   through the object.
    //            /// </returns>
    //            /// <remarks>
    //            ///   The enumerator will enumerate the properties in the order they are
    //            ///   declared, and when an object has multiple definitions of a single
    //            ///   property they will all individually be returned (each in the order
    //            ///   they appear in the content).
    //            /// </remarks>
    //            public ObjectEnumerator GetEnumerator()
    //            {
    //                ObjectEnumerator ator = this;
    //                ator._curIdx = -1;
    //                return ator;
    //            }

    //            /// <inheritdoc />
    //            IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    //            /// <inheritdoc />
    //            IEnumerator<JwtProperty2> IEnumerable<JwtProperty2>.GetEnumerator() => GetEnumerator();

    //            /// <inheritdoc />
    //            public void Dispose()
    //            {
    //                _curIdx = _endIdxOrVersion;
    //            }

    //            /// <inheritdoc />
    //            public void Reset()
    //            {
    //                _curIdx = -1;
    //            }

    //            /// <inheritdoc />
    //            object IEnumerator.Current => Current;

    //            /// <inheritdoc />
    //            public bool MoveNext()
    //            {
    //                if (_curIdx >= _endIdxOrVersion)
    //                {
    //                    return false;
    //                }

    //                if (_curIdx < 0)
    //                {
    //                    _curIdx = _target._idx + JwtPayloadDocument.DbRow.Size;
    //                }
    //                else
    //                {
    //                    _curIdx = _target._parent.GetEndIndex(_curIdx, includeEndElement: true);
    //                }

    //                // _curIdx is now pointing at a property name, move one more to get the value
    //                _curIdx += JwtPayloadDocument.DbRow.Size;

    //                return _curIdx < _endIdxOrVersion;
    //            }
    //        }

    //        /// <summary>
    //        ///   An enumerable and enumerator for the contents of a JSON array.
    //        /// </summary>
    //        [DebuggerDisplay("{Current,nq}")]
    //        public struct ArrayEnumerator : IEnumerable<JwtElement>, IEnumerator<JwtElement>
    //        {
    //            private readonly JwtElement _target;
    //            private int _curIdx;
    //            private readonly int _endIdxOrVersion;

    //            internal ArrayEnumerator(JwtElement target)
    //            {
    //                _target = target;
    //                _curIdx = -1;

    //                Debug.Assert(target.TokenType == JsonTokenType.StartArray);

    //                _endIdxOrVersion = target._parent.GetEndIndex(_target._idx, includeEndElement: false);
    //            }

    //            /// <inheritdoc />
    //            public JwtElement Current
    //            {
    //                get
    //                {
    //                    if (_curIdx < 0)
    //                    {
    //                        return default;
    //                    }

    //                    return new JwtElement(_target._parent, _curIdx);
    //                }
    //            }

    //            /// <summary>
    //            ///   Returns an enumerator that iterates through a collection.
    //            /// </summary>
    //            /// <returns>
    //            ///   An <see cref="ArrayEnumerator"/> value that can be used to iterate
    //            ///   through the array.
    //            /// </returns>
    //            public ArrayEnumerator GetEnumerator()
    //            {
    //                ArrayEnumerator ator = this;
    //                ator._curIdx = -1;
    //                return ator;
    //            }

    //            /// <inheritdoc />
    //            IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    //            /// <inheritdoc />
    //            IEnumerator<JwtElement> IEnumerable<JwtElement>.GetEnumerator() => GetEnumerator();

    //            /// <inheritdoc />
    //            public void Dispose()
    //            {
    //                _curIdx = _endIdxOrVersion;
    //            }

    //            /// <inheritdoc />
    //            public void Reset()
    //            {
    //                _curIdx = -1;
    //            }

    //            /// <inheritdoc />
    //            object IEnumerator.Current => Current;

    //            /// <inheritdoc />
    //            public bool MoveNext()
    //            {
    //                if (_curIdx >= _endIdxOrVersion)
    //                {
    //                    return false;
    //                }

    //                if (_curIdx < 0)
    //                {
    //                    _curIdx = _target._idx + JwtPayloadDocument.DbRow.Size;
    //                }
    //                else
    //                {
    //                    _curIdx = _target._parent.GetEndIndex(_curIdx, includeEndElement: true);
    //                }

    //                return _curIdx < _endIdxOrVersion;
    //            }
    //        }
    //    }

    //    /// <summary>
    //    ///   Represents a single property for a JSON object.
    //    /// </summary>
    //    [DebuggerDisplay("{DebuggerDisplay,nq}")]
    //    public readonly struct JwtProperty2
    //    {
    //        /// <summary>
    //        ///   The value of this property.
    //        /// </summary>
    //        public JwtElement Value { get; }
    //        private string? _name { get; }

    //        internal JwtProperty2(JwtElement value, string? name = null)
    //        {
    //            Value = value;
    //            _name = name;
    //        }

    //        /// <summary>
    //        ///   The name of this property.
    //        /// </summary>
    //        public string Name => _name ?? Value.GetPropertyName();

    //        /// <summary>
    //        ///   Compares <paramref name="text" /> to the name of this property.
    //        /// </summary>
    //        /// <param name="text">The text to compare against.</param>
    //        /// <returns>
    //        ///   <see langword="true" /> if the name of this property matches <paramref name="text"/>,
    //        ///   <see langword="false" /> otherwise.
    //        /// </returns>
    //        /// <exception cref="InvalidOperationException">
    //        ///   This value's <see cref="Type"/> is not <see cref="JsonTokenType.PropertyName"/>.
    //        /// </exception>
    //        /// <remarks>
    //        ///   This method is functionally equal to doing an ordinal comparison of <paramref name="text" /> and
    //        ///   <see cref="Name" />, but can avoid creating the string instance.
    //        /// </remarks>
    //        public bool NameEquals(string? text)
    //        {
    //            return NameEquals(text.AsSpan());
    //        }

    //        /// <summary>
    //        ///   Compares the text represented by <paramref name="utf8Text" /> to the name of this property.
    //        /// </summary>
    //        /// <param name="utf8Text">The UTF-8 encoded text to compare against.</param>
    //        /// <returns>
    //        ///   <see langword="true" /> if the name of this property has the same UTF-8 encoding as
    //        ///   <paramref name="utf8Text" />, <see langword="false" /> otherwise.
    //        /// </returns>
    //        /// <exception cref="InvalidOperationException">
    //        ///   This value's <see cref="Type"/> is not <see cref="JsonTokenType.PropertyName"/>.
    //        /// </exception>
    //        /// <remarks>
    //        ///   This method is functionally equal to doing an ordinal comparison of <paramref name="utf8Text" /> and
    //        ///   <see cref="Name" />, but can avoid creating the string instance.
    //        /// </remarks>
    //        public bool NameEquals(ReadOnlySpan<byte> utf8Text)
    //        {
    //            return Value.TextEqualsHelper(utf8Text, isPropertyName: true, shouldUnescape: true);
    //        }

    //        /// <summary>
    //        ///   Compares <paramref name="text" /> to the name of this property.
    //        /// </summary>
    //        /// <param name="text">The text to compare against.</param>
    //        /// <returns>
    //        ///   <see langword="true" /> if the name of this property matches <paramref name="text"/>,
    //        ///   <see langword="false" /> otherwise.
    //        /// </returns>
    //        /// <exception cref="InvalidOperationException">
    //        ///   This value's <see cref="Type"/> is not <see cref="JsonTokenType.PropertyName"/>.
    //        /// </exception>
    //        /// <remarks>
    //        ///   This method is functionally equal to doing an ordinal comparison of <paramref name="text" /> and
    //        ///   <see cref="Name" />, but can avoid creating the string instance.
    //        /// </remarks>
    //        public bool NameEquals(ReadOnlySpan<char> text)
    //        {
    //            return Value.TextEqualsHelper(text, isPropertyName: true);
    //        }

    //        internal bool EscapedNameEquals(ReadOnlySpan<byte> utf8Text)
    //        {
    //            return Value.TextEqualsHelper(utf8Text, isPropertyName: true, shouldUnescape: false);
    //        }

    //        ///// <summary>
    //        /////   Write the property into the provided writer as a named JSON object property.
    //        ///// </summary>
    //        ///// <param name="writer">The writer.</param>
    //        ///// <exception cref="ArgumentNullException">
    //        /////   The <paramref name="writer"/> parameter is <see langword="null"/>.
    //        ///// </exception>
    //        ///// <exception cref="ArgumentException">
    //        /////   This <see cref="Name"/>'s length is too large to be a JSON object property.
    //        ///// </exception>
    //        ///// <exception cref="InvalidOperationException">
    //        /////   This <see cref="Value"/>'s <see cref="JsonElement.ValueKind"/> would result in an invalid JSON.
    //        ///// </exception>
    //        ///// <exception cref="ObjectDisposedException">
    //        /////   The parent <see cref="JsonDocument"/> has been disposed.
    //        ///// </exception>>
    //        //public void WriteTo(Utf8JsonWriter writer)
    //        //{
    //        //    if (writer == null)
    //        //    {
    //        //        throw new ArgumentNullException(nameof(writer));
    //        //    }

    //        //    writer.WritePropertyName(Name);
    //        //    Value.WriteTo(writer);
    //        //}

    //        /// <summary>
    //        ///   Provides a <see cref="string"/> representation of the property for
    //        ///   debugging purposes.
    //        /// </summary>
    //        /// <returns>
    //        ///   A string containing the un-interpreted value of the property, beginning
    //        ///   at the declaring open-quote and ending at the last character that is part of
    //        ///   the value.
    //        /// </returns>
    //        public override string ToString()
    //        {
    //            return Value.GetPropertyRawText();
    //        }

    //        private string DebuggerDisplay
    //            => Value.ValueKind == JsonValueKind.Undefined ? "<Undefined>" : $"\"{ToString()}\"";
    //    }
}