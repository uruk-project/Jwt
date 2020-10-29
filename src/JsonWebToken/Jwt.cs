using System;
using System.Buffers;
using System.Collections.Generic;
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
    public class Jwt : IDisposable
    {
        private ReadOnlyMemory<byte> _rawValue;
        private byte[]? _rented;
        private readonly JwtHeaderDocument _header;
        private readonly JwtPayloadDocument? _payload;
        private readonly Jwt? _nested;
        private readonly TokenValidationError? _error;

        internal Jwt(Jwt other)
        {
            _rawValue = other._rawValue;
            _rented = other._rented;
            _header = other._header;
            _payload = other._payload;
            _nested = other._nested;
            _error = other._error;
        }

        internal Jwt(TokenValidationError error)
        {
            _header = JwtHeaderDocument.Empty;
            _error = error;
        }

        private Jwt(JwtHeaderDocument header, ReadOnlyMemory<byte> rawValue, byte[] rented)
        {
            _header = header;
            _rawValue = rawValue;
            _rented = rented;
        }

        private Jwt(JwtHeaderDocument header, Jwt nested, byte[] rented)
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

        private Jwt(JwtHeaderDocument header, JwtPayloadDocument payload, TokenValidationError error)
        {
            _header = header;
            _payload = payload;
            _error = error;
        }

        private Jwt(JwtHeaderDocument header, Jwt nested, TokenValidationError error, byte[] rented)
        {
            _header = header;
            _payload = nested.Payload;
            _nested = nested;
            _error = error;
            _rented = rented;
        }

        /// <summary>
        /// Gets the eventual error of the current <see cref="Jwt"/>.
        /// </summary>
        public TokenValidationError? Error => _error;

        /// <summary>
        /// Gets the header of the current <see cref="Jwt"/>.
        /// </summary>
        public JwtHeaderDocument Header => _header;

        /// <summary>
        /// Gets the payload of the current <see cref="Jwt"/>.
        /// </summary>
        public JwtPayloadDocument? Payload => _payload;

        /// <summary>
        /// Gets the nested <see cref="Jwt"/> of the current <see cref="Jwt"/>, if any.
        /// </summary>
        public Jwt? Nested => _nested;

        /// <summary>
        /// Gets the raw binary value of the current <see cref="Jwt"/>.
        /// </summary>
        public ReadOnlyMemory<byte> RawValue => _rawValue;

        /// <summary>
        /// Gets the <see cref="string"/> representation of the current <see cref="Jwt"/>.
        /// </summary>
        public string Plaintext => Utf8.GetString(_rawValue.Span);

        /// <summary>
        /// Parses and validates a JWT encoded as a JWS or JWE in compact serialized format.
        /// </summary>
        /// <param name="token">The JWT encoded as JWE or JWS</param>
        /// <param name="policy">The validation policy.</param>
        /// <param name="jwt">The resulting <see cref="Jwt"/>.</param>
        public static bool TryParse(string token, TokenValidationPolicy policy, out Jwt jwt)
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
                jwt = new Jwt(TokenValidationError.MalformedToken());
                return false;
            }

            int length = Utf8.GetMaxByteCount(token.Length);
            if (length > policy.MaximumTokenSizeInBytes)
            {
                jwt = new Jwt(TokenValidationError.MalformedToken());
                return false;
            }

            byte[]? utf8ArrayToReturnToPool = null;
            var utf8Token = length <= Constants.MaxStackallocBytes
                  ? stackalloc byte[length]
                  : (utf8ArrayToReturnToPool = ArrayPool<byte>.Shared.Rent(length));
            try
            {
                int bytesWritten = Utf8.GetBytes(token, utf8Token);
                return TryParse(utf8Token.Slice(0, bytesWritten), policy, out jwt);
            }
            finally
            {
                if (utf8ArrayToReturnToPool != null)
                {
                    ArrayPool<byte>.Shared.Return(utf8ArrayToReturnToPool);
                }
            }
        }

        /// <summary>
        /// Parses and validates a JWT encoded as a JWS or JWE in compact serialized format.
        /// </summary>
        /// <param name="utf8Token">The JWT encoded as JWE or JWS.</param>
        /// <param name="policy">The validation policy.</param>
        /// <param name="jwt">The resulting <see cref="Jwt"/>.</param>
        public static bool TryParse(in ReadOnlySequence<byte> utf8Token, TokenValidationPolicy policy, out Jwt jwt)
        {
            if (utf8Token.IsSingleSegment)
            {
                return TryParse(utf8Token.First.Span, policy, out jwt);
            }

            return TryParse(utf8Token.ToArray(), policy, out jwt);
        }

        /// <summary>
        /// Parses and validates a JWT encoded as a JWS or JWE in compact serialized format.
        /// </summary>
        /// <param name="utf8Token">The JWT encoded as JWE or JWS</param>
        /// <param name="policy">The validation policy.</param>
        /// <param name="jwt">The resulting <see cref="Jwt"/>.</param>
        public static bool TryParse(ReadOnlySpan<byte> utf8Token, TokenValidationPolicy policy, out Jwt jwt)
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
                JwtHeaderDocument? header;
                bool validHeader;
                if (policy.HeaderCache.Enabled)
                {
                    if (!policy.HeaderCache.TryGetHeader(rawHeader, out header))
                    {
                        int decodedHeaderLength = Base64Url.Decode(rawHeader, new Span<byte>(jsonBuffer, 0, jsonBuffer.Length));
                        Debug.Assert(headerJsonDecodedLength == decodedHeaderLength);
                        if (validHeader = TryReadHeader(new ReadOnlyMemory<byte>(jsonBuffer, 0, decodedHeaderLength), policy, out header, out error))
                        {
                            policy.HeaderCache.AddHeader(rawHeader, header!);
                        }
                    }
                    else
                    {
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
                    Debug.Assert(header != null);
                    wellFormedJwt = segmentCount switch
                    {
                        Constants.JwsSegmentCount => TryReadJws(utf8Token, jsonBuffer, headerJsonDecodedLength, payloadjsonDecodedLength, policy, ref segmentsRef, header!, out jwt),
                        Constants.JweSegmentCount => TryReadJwe(utf8Token, jsonBuffer, headerJsonDecodedLength, payloadjsonDecodedLength, policy, rawHeader, ref segmentsRef, header!, out jwt),
                        _ => InvalidDocument(TokenValidationError.MalformedToken($"JWT must have 3 or 5 segments. The current token has {segmentCount} segments."), out jwt),
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
            Debug.Assert(error != null);
            return InvalidDocument(error!, out jwt);

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
                if (JwtPayloadDocument.TryParse(
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
            if (JwtReaderHelper.TryDecryptToken(keys, rawHeader, rawCiphertext, rawInitializationVector, rawAuthenticationTag, encryptionAlgorithm, decryptedBytes, out int bytesWritten))
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
                    if (nestedDocument.Error!.Status == TokenValidationStatus.MalformedToken && !policy.HasValidation)
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
                        document = new Jwt(header, nestedDocument, nestedDocument.Error, jsonBuffer);
                        goto CompleteError;
                    }
                }
            }

            document = jwe;
            return true;

        Error:
            document = new Jwt(error);
        CompleteError:
            ArrayPool<byte>.Shared.Return(jsonBuffer);
            return false;
        }

        /// <inheritdoc />
        public virtual void Dispose()
        {
            _rawValue = ReadOnlyMemory<byte>.Empty;
            _payload?.Dispose();
            byte[]? rented = Interlocked.Exchange(ref _rented, null);
            if (rented != null)
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }

        /// <inheritsdoc />
        public override string ToString()
        {
            if (_payload == null)
            {
                return _header.ToString() + ".";
            }
            else if (_nested == null)
            {
                return _header.ToString() + "." + _payload.ToString();
            }
            else
            {
                return _header.ToString() + "." + _nested._header.ToString() + "." + _nested._payload;
            }
        }
    }
}