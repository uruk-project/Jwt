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
    public sealed class JwtDocument2 : IDisposable
    {
        private ReadOnlyMemory<byte> _rawValue;
        private byte[]? _rented;
        private readonly JwtHeaderDocument2 _header;
        private readonly JwtPayloadDocumentOld? _payload;
        private readonly JwtDocument2? _nested;
        private readonly TokenValidationError? _error;

        public JwtDocument2(JwtHeaderDocument2 header, ReadOnlyMemory<byte> rawValue, byte[] rented)
        {
            _header = header;
            _rawValue = rawValue;
            _rented = rented;
        }

        public JwtDocument2(TokenValidationError error)
        {
            _error = error;
        }

        public JwtDocument2(TokenValidationError error, byte[] rented)
        {
            _error = error;
            _rented = rented;
        }

        public JwtDocument2(JwtHeaderDocument2 header, JwtDocument2 nested, byte[] rented)
        {
            _header = header;
            _payload = nested.Payload;
            _nested = nested;
            _rented = rented;
        }

        public JwtDocument2(JwtHeaderDocument2 header, JwtPayloadDocumentOld payload)
        {
            _header = header;
            _payload = payload;
        }

        public JwtDocument2(JwtHeaderDocument2 header, JwtPayloadDocumentOld payload, TokenValidationError error)
        {
            _header = header;
            _payload = payload;
            _error = error;
        }

        public JwtDocument2(JwtHeaderDocument2 header, JwtDocument2 nested, TokenValidationError error, byte[] rented)
        {
            _header = header;
            _payload = nested.Payload;
            _nested = nested;
            _error = error;
            _rented = rented;
        }

        public TokenValidationError? Error => _error;
        public JwtHeaderDocument2? Header => _header;
        public JwtPayloadDocumentOld? Payload => _payload;
        public JwtDocument2? Nested => _nested;
        public ReadOnlyMemory<byte> RawValue => _rawValue;

        public static bool TryParse2(ReadOnlySpan<byte> utf8Token, TokenValidationPolicy policy, out JwtDocument2 document)
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

            JwtHeaderDocument2? header;
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
                        validHeader = TryReadHeader(new ReadOnlyMemory<byte>(jsonBuffer, 0, decodedHeaderLength), policy, segmentCount, out header, out error);
                        policy.HeaderCache.AddHeader(rawHeader, header);
                    }
                    else
                    {
                        header = (JwtHeaderDocument2)tmp;
                        validHeader = policy.TryValidateHeader(header, out error);
                    }
                }
                else
                {
                    int decodedHeaderLength = Base64Url.Decode(rawHeader, jsonBuffer);
                    validHeader = TryReadHeader(new ReadOnlyMemory<byte>(jsonBuffer, 0, decodedHeaderLength), policy, segmentCount, out header, out error);
                }

                if (validHeader)
                {
                    return segmentCount switch
                    {
                        Constants.JwsSegmentCount => TryReadJws(utf8Token, jsonBuffer, headerJsonDecodedLength, payloadjsonDecodedLength, policy, ref segmentsRef, header, out document),
                        Constants.JweSegmentCount => TryReadJwe(utf8Token, jsonBuffer, headerJsonDecodedLength, payloadjsonDecodedLength, policy, rawHeader, ref segmentsRef, header, out document),
                        _ => InvalidDocument(TokenValidationError.MalformedToken(), out document),
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

            static bool InvalidDocument(TokenValidationError error, out JwtDocument2 document)
            {
                document = new JwtDocument2(error);
                return false;
            }
        }

        internal static bool TryReadBase64Header(ReadOnlySpan<byte> utf8Header, TokenValidationPolicy policy, int segmentCount, out JwtHeaderDocument2 header, out TokenValidationError? error)
        {
            int headerJsonDecodedLength = Base64Url.GetArraySizeRequiredToDecode((int)utf8Header.Length);
            var headerBufferToReturnToPool = ArrayPool<byte>.Shared.Rent(headerJsonDecodedLength);
            try
            {
                Base64Url.Decode(utf8Header, headerBufferToReturnToPool);
                return TryReadHeader(new ReadOnlyMemory<byte>(headerBufferToReturnToPool, 0, headerJsonDecodedLength), policy, segmentCount, out header, out error);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(headerBufferToReturnToPool);
            }
        }

        internal static bool TryReadHeader(ReadOnlyMemory<byte> utf8Header, TokenValidationPolicy policy, int segmentCount, out JwtHeaderDocument2 header, [NotNullWhen(false)] out TokenValidationError? error)
        {
            header = new JwtHeaderDocument2(JsonDocument.Parse(utf8Header));
            //header = new JwtHeader();
            //bool result;
            //var reader = new JwtHeaderReader(utf8Header, policy);
            //if (reader.ReadFirstBytes())
            //{
            //    while (reader.Read())
            //    {
            //        var name = reader.TokenName;
            //        switch (reader.TokenType)
            //        {
            //            case JsonTokenType.StartObject:
            //                header.Inner.Add(name, reader.GetJwtObject());
            //                break;
            //            case JsonTokenType.StartArray:
            //                if (reader.TokenName.Length == 4 && IntegerMarshal.ReadUInt32(reader.TokenName) == (uint)JwtHeaderParameters.Crit)
            //                {
            //                    var crit = reader.GetCriticalHeaders();
            //                    header.Inner.Add(name, new JwtArray(crit.Item1));
            //                    header.CriticalHeaderHandlers = crit.Item2;
            //                    continue;
            //                }

            //                header.Inner.Add(name, reader.GetJwtArray());
            //                break;
            //            case JsonTokenType.String:
            //                if (reader.TokenName.Length == 3)
            //                {
            //                    switch ((JwtHeaderParameters)IntegerMarshal.ReadUInt24(reader.TokenName))
            //                    {
            //                        case JwtHeaderParameters.Alg:
            //                            if (segmentCount == Constants.JwsSegmentCount)
            //                            {
            //                                header.SignatureAlgorithm = reader.GetSignatureAlgorithm();
            //                            }
            //                            else if (segmentCount == Constants.JweSegmentCount)
            //                            {
            //                                header.KeyManagementAlgorithm = reader.GetKeyManagementAlgorithm();
            //                            }
            //                            continue;
            //                        case JwtHeaderParameters.Enc:
            //                            header.EncryptionAlgorithm = reader.GetEncryptionAlgorithm();
            //                            continue;
            //                        case JwtHeaderParameters.Zip:
            //                            header.CompressionAlgorithm = reader.GetCompressionAlgorithm();
            //                            continue;
            //                        case JwtHeaderParameters.Cty:
            //                            header.Cty = reader.GetString();
            //                            continue;
            //                        case JwtHeaderParameters.Typ:
            //                            header.Typ = reader.GetString();
            //                            continue;
            //                        case JwtHeaderParameters.Kid:
            //                            header.Kid = reader.GetString();
            //                            continue;
            //                    }
            //                }

            //                header.Inner.Add(name, reader.GetString()!);
            //                break;
            //            case JsonTokenType.True:
            //                header.Inner.Add(name, true);
            //                break;
            //            case JsonTokenType.False:
            //                header.Inner.Add(name, false);
            //                break;
            //            case JsonTokenType.Null:
            //                header.Inner.Add(name);
            //                break;
            //            case JsonTokenType.Number:
            //                if (reader.TryGetInt64(out long longValue))
            //                {
            //                    header.Inner.Add(name, longValue);
            //                }
            //                else
            //                {
            //                    header.Inner.Add(name, reader.GetDouble());
            //                }
            //                break;
            //        }
            //    }

            //if (reader.TokenType is JsonTokenType.EndObject)
            //{
            //result = reader.TryValidateHeader(header, out error);
            //    }
            //    else
            //    {
            //        result = false;
            //        error = TokenValidationError.MalformedToken();
            //    }
            //}
            //else
            //{
            //    result = false;
            //    error = TokenValidationError.MalformedToken();
            //}

            return policy.TryValidateHeader(header, out error);
        }

        private static bool TryReadJws(
            ReadOnlySpan<byte> utf8Buffer,
            byte[] jsonBuffer,
            int jsonBufferOffset,
            int jsonBufferLength,
            TokenValidationPolicy policy,
            ref TokenSegment segments,
            JwtHeaderDocument2 header,
            out JwtDocument2? jwt)
        {
            TokenSegment headerSegment = segments;
            TokenSegment payloadSegment = Unsafe.Add(ref segments, 1);
            TokenSegment signatureSegment = Unsafe.Add(ref segments, 2);
            var rawPayload = utf8Buffer.Slice(payloadSegment.Start, payloadSegment.Length);
            var result = policy.TryValidateSignature(header, utf8Buffer.Slice(headerSegment.Start, headerSegment.Length + payloadSegment.Length + 1), utf8Buffer.Slice(signatureSegment.Start, signatureSegment.Length));
            if (!result.Succedeed)
            {
                jwt = new JwtDocument2(TokenValidationError.SignatureValidationFailed(result));
                return false;
            }

            Exception malformedException;
            try
            {
                int bytesWritten = Base64Url.Decode(rawPayload, new Span<byte>(jsonBuffer, jsonBufferOffset, jsonBufferLength));
                Debug.Assert(bytesWritten == jsonBufferLength);
                if (TryReadPayload(new ReadOnlyMemory<byte>(jsonBuffer, jsonBufferOffset, jsonBufferLength), out JwtPayloadDocumentOld? payload, out TokenValidationError? error))
                {
                    if (policy.TryValidateJwt(header, payload, out error))
                    {
                        jwt = new JwtDocument2(header, payload);
                        return true;
                    }
                    else
                    {
                        jwt = new JwtDocument2(header, payload, error);
                        return false;
                    }
                }
                else
                {
                    jwt = new JwtDocument2(error);
                    return false;
                }
            }
            catch (FormatException formatException)
            {
                malformedException = formatException;
                goto Malformed;
            }
            catch (JsonException readerException)
            {
                malformedException = readerException;
                goto Malformed;
            }
            catch (InvalidOperationException invalidOperationException) when (invalidOperationException.InnerException is DecoderFallbackException)
            {
                malformedException = invalidOperationException;
                goto Malformed;
            }


        Malformed:
            jwt = new JwtDocument2(TokenValidationError.MalformedToken(exception: malformedException));
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
            JwtHeaderDocument2 header,
            out JwtDocument2 document)
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

            JwtDocument2 jwe;
            if (policy.IgnoreNestedToken)
            {
                ReadOnlyMemory<byte> rawValue = compressed
                    ? decompressedBytes.IsSingleSegment
                        ? decompressedBytes.First
                        : decompressedBytes.ToArray()
                    : new ReadOnlyMemory<byte>(jsonBuffer, jsonBufferOffset, bytesWritten);
                jwe = new JwtDocument2(header, rawValue, jsonBuffer);
            }
            else
            {
                bool decrypted = compressed
                    ? TryParse(decompressedBytes, policy, out var nestedDocument)
                    : TryParse2(decryptedBytes, policy, out nestedDocument);
                if (decrypted)
                {
                    jwe = new JwtDocument2(header, nestedDocument, jsonBuffer);
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
                        jwe = new JwtDocument2(header, rawValue, jsonBuffer);
                    }
                    else
                    {
                        jwe = new JwtDocument2(header, nestedDocument, nestedDocument.Error, jsonBuffer);
                    }
                }
            }

            document = jwe;
            return true;

        Error:
            document = new JwtDocument2(error, jsonBuffer);
            return false;
        }

        public static bool TryReadPayload(ReadOnlyMemory<byte> utf8Payload, [NotNullWhen(true)] out JwtPayloadDocumentOld? payload, [NotNullWhen(false)] out TokenValidationError? error)
        {
            try
            {
                payload = new JwtPayloadDocumentOld(JsonDocument.Parse(utf8Payload));
                error = null;
                return true;
            }
            catch (Exception e)
            {
                error = TokenValidationError.MalformedToken(e);
                payload = null;
                return false;
            }
        }

        public static bool TryParse(ReadOnlySequence<byte> utf8Token, TokenValidationPolicy policy, out JwtDocument2 document)
        {
            if (utf8Token.IsSingleSegment)
            {
                return TryParse2(utf8Token.First.Span, policy, out document);
            }

            return TryParse2(utf8Token.ToArray(), policy, out document);
        }

        /// <summary>
        /// Reads and validates a JWT encoded as a JWS or JWE in compact serialized format.
        /// </summary>
        /// <param name="token">The JWT encoded as JWE or JWS</param>
        /// <param name="policy">The validation policy.</param>
        public static bool TryParse(string token, TokenValidationPolicy policy, out JwtDocument2 document)
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
                document = new JwtDocument2(TokenValidationError.MalformedToken());
                return false;
            }

            int length = Utf8.GetMaxByteCount(token.Length);
            if (length > policy.MaximumTokenSizeInBytes)
            {
                document = new JwtDocument2(TokenValidationError.MalformedToken());
                return false;
            }

            byte[]? utf8ArrayToReturnToPool = null;
            var utf8Token = length <= Constants.MaxStackallocBytes
                  ? stackalloc byte[length]
                  : (utf8ArrayToReturnToPool = ArrayPool<byte>.Shared.Rent(length));
            try
            {
                int bytesWritten = Utf8.GetBytes(token, utf8Token);
                return TryParse2(utf8Token.Slice(0, bytesWritten), policy, out document);
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
            byte[]? rented = Interlocked.Exchange(ref _rented, null);
            if (rented != null)
            {
                ArrayPool<byte>.Shared.Return(rented);
            }

            _header.Dispose();
            if (_payload != null)
            {
                _payload.Dispose();
            }
        }
    }
}