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
using JsonWebToken.Cryptography;

namespace JsonWebToken
{
    /// <summary>Represents the structure of a JWT value in a read-only form.</summary>
    /// <remarks>
    /// This class utilizes resources from pooled memory to minimize the garbage collector (GC)
    /// impact in high-usage scenarios. Failure to properly Dispose this object will result in
    /// the memory not being returned to the pool, which will cause an increase in GC impact across
    /// various parts of the framework.
    /// </remarks>
    // Inspired from https://github.com/dotnet/runtime/tree/master/src/libraries/System.Text.Json/src/System/Text/Json/Document
    public sealed partial class Jwt : IDisposable
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

        internal Jwt(JwtHeaderDocument header, JwtPayloadDocument payload)
        {
            _header = header;
            _payload = payload;
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

        /// <summary>Gets the eventual error of the current <see cref="Jwt"/>.</summary>
        public TokenValidationError? Error => _error;

        /// <summary>Gets the header of the current <see cref="Jwt"/>.</summary>
        public JwtHeaderDocument Header => _header;

        /// <summary>Gets the payload of the current <see cref="Jwt"/>.</summary>
        public JwtPayloadDocument? Payload => _payload;

        /// <summary>Gets the nested <see cref="Jwt"/> of the current <see cref="Jwt"/>, if any.</summary>
        public Jwt? Nested => _nested;

        /// <summary>Gets the raw binary value of the current <see cref="Jwt"/>.</summary>
        public ReadOnlyMemory<byte> RawValue => _rawValue;

        /// <summary>Gets the <see cref="string"/> representation of the current <see cref="Jwt"/>.</summary>
        public string Plaintext => Utf8.GetString(_rawValue.Span);

        /// <summary>Parses and validates a JWT encoded as a JWS or JWE in compact serialized format.</summary>
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
            // Useful for b64?
            int length = Utf8.GetMaxByteCount(token.Length);
            if (length > policy.MaximumTokenSizeInBytes)
            {
                jwt = new Jwt(TokenValidationError.MalformedToken());
                return false;
            }

            byte[]? utf8ArrayToReturnToPool = null;
            var utf8Token = length > Constants.MaxStackallocBytes
                  ? (utf8ArrayToReturnToPool = ArrayPool<byte>.Shared.Rent(length))
                  : stackalloc byte[Constants.MaxStackallocBytes];
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

        /// <summary>Parses and validates a JWT encoded as a JWS or JWE in compact serialized format.</summary>
        /// <param name="utf8Token">The JWT encoded as JWE or JWS.</param>
        /// <param name="policy">The validation policy.</param>
        /// <param name="jwt">The resulting <see cref="Jwt"/>.</param>
        public static bool TryParse(ReadOnlySequence<byte> utf8Token, TokenValidationPolicy policy, out Jwt jwt)
        {
            if (utf8Token.IsSingleSegment)
            {
                return TryParse(utf8Token.First.Span, policy, out jwt);
            }

            return TryParse(utf8Token.ToArray(), policy, out jwt);
        }

        /// <summary>Parses and validates a JWT encoded as a JWS or JWE in compact serialized format.</summary>
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
                goto TokenError;
            }

            if (utf8Token.Length > policy.MaximumTokenSizeInBytes)
            {
                error = TokenValidationError.MalformedToken();
                goto TokenError;
            }

            Span<TokenSegment> segments = stackalloc TokenSegment[Constants.JweSegmentCount];
            ref TokenSegment segmentsRef = ref MemoryMarshal.GetReference(segments);
            int segmentCount = Tokenizer.Tokenize(utf8Token, ref segmentsRef);
            if (segmentCount < Constants.JwsSegmentCount)
            {
                error = TokenValidationError.MalformedToken();
                goto TokenError;
            }

            var headerSegment = segmentsRef;
            if (headerSegment.IsEmpty)
            {
                error = TokenValidationError.MalformedToken();
                goto TokenError;
            }

            var rawHeader = utf8Token.Slice(0, headerSegment.Length);
            int headerJsonDecodedLength = Base64Url.GetArraySizeRequiredToDecode(rawHeader.Length);

            byte[] jsonHeaderBuffer = ArrayPool<byte>.Shared.Rent(headerJsonDecodedLength);
            bool wellFormedJwt = false;
            try
            {
                JwtHeaderDocument? header;
                if (policy.HeaderCache.Enabled)
                {
                    if (!policy.HeaderCache.TryGetHeader(rawHeader, out header))
                    {
                        int decodedHeaderLength = Base64Url.Decode(rawHeader, new Span<byte>(jsonHeaderBuffer, 0, jsonHeaderBuffer.Length));
                        Debug.Assert(headerJsonDecodedLength == decodedHeaderLength);
                        if (!JwtHeaderDocument.TryParseHeader(new ReadOnlyMemory<byte>(jsonHeaderBuffer, 0, headerJsonDecodedLength), jsonHeaderBuffer, policy, out header, out error))
                        {
                            goto TokenError;
                        }

                        if (!policy.TryValidateHeader(header, out error))
                        {
                            goto TokenError;
                        }

                        policy.HeaderCache.AddHeader(rawHeader, header);
                    }
                    else
                    {
                        if (!policy.TryValidateHeader(header, out error))
                        {
                            goto TokenError;
                        }
                    }
                }
                else
                {
                    int decodedHeaderLength = Base64Url.Decode(rawHeader, new Span<byte>(jsonHeaderBuffer, 0, jsonHeaderBuffer.Length));
                    Debug.Assert(headerJsonDecodedLength == decodedHeaderLength);
                    if (!JwtHeaderDocument.TryParseHeader(new ReadOnlyMemory<byte>(jsonHeaderBuffer, 0, headerJsonDecodedLength), jsonHeaderBuffer, policy, out header, out error))
                    {
                        goto TokenError;
                    }

                    if (!policy.TryValidateHeader(header, out error))
                    {
                        goto TokenError;
                    }
                }

                Debug.Assert(header != null);
                wellFormedJwt = segmentCount switch
                {
                    Constants.JwsSegmentCount => TryParseJws(utf8Token, policy, ref segmentsRef, header!, out jwt),
                    Constants.JweSegmentCount => TryParseJwe(utf8Token, policy, rawHeader, ref segmentsRef, header!, out jwt),
                    _ => InvalidDocument(TokenValidationError.MalformedToken($"JWT must have 3 or 5 segments. The current token has {segmentCount} segments."), out jwt),
                };
                return wellFormedJwt;
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
            catch
            {
                ArrayPool<byte>.Shared.Return(jsonHeaderBuffer);
                throw;
            }

            ArrayPool<byte>.Shared.Return(jsonHeaderBuffer);

        TokenError:
            Debug.Assert(error != null);
            return InvalidDocument(error!, out jwt);

            static bool InvalidDocument(TokenValidationError error, out Jwt document)
            {
                document = new Jwt(error);
                return false;
            }
        }

        private static bool TryParseJws(
            ReadOnlySpan<byte> utf8Token,
            TokenValidationPolicy policy,
            ref TokenSegment segments,
            JwtHeaderDocument header,
            out Jwt jwt)
        {
            TokenSegment headerSegment = segments;
            TokenSegment payloadSegment = Unsafe.Add(ref segments, 1);
            TokenSegment signatureSegment = Unsafe.Add(ref segments, 2);
            var rawPayload = utf8Token.Slice(payloadSegment.Start, payloadSegment.Length);

            int jsonBufferLength = Base64Url.GetArraySizeRequiredToDecode(payloadSegment.Length);
            byte[] jsonBuffer = ArrayPool<byte>.Shared.Rent(jsonBufferLength);

            try
            {
                int bytesWritten = Base64Url.Decode(rawPayload, jsonBuffer);
                if (!JwtPayloadDocument.TryParsePayload(
                    new ReadOnlyMemory<byte>(jsonBuffer, 0, jsonBufferLength),
                    jsonBuffer,
                    policy,
                    out JwtPayloadDocument? payload,
                    out TokenValidationError? error))
                {
                    jwt = new Jwt(error);
                    goto ExitFalseClearBuffer;
                }

                if (!policy.TryValidateSignature(
                    header,
                    payload,
                    utf8Token.Slice(headerSegment.Start, headerSegment.Length + payloadSegment.Length + 1),
                    utf8Token.Slice(signatureSegment.Start, signatureSegment.Length), out var signatureError))
                {
                    jwt = new Jwt(TokenValidationError.SignatureValidationFailed(signatureError));
                    goto ExitFalse;
                }

                if (!policy.TryValidateJwt(header, payload, out error))
                {
                    jwt = new Jwt(header, payload, error);
                    goto ExitFalse;
                }

                jwt = new Jwt(header, payload);
                return true;
            }
            catch (FormatException formatException)
            {
                jwt = new Jwt(TokenValidationError.MalformedToken(formatException));
                goto ExitFalseClearBuffer;
            }
            catch (JsonException readerException)
            {
                jwt = new Jwt(TokenValidationError.MalformedToken(readerException));
                goto ExitFalseClearBuffer;
            }
            catch (InvalidOperationException invalidOperationException) when (invalidOperationException.InnerException is DecoderFallbackException)
            {
                jwt = new Jwt(TokenValidationError.MalformedToken(invalidOperationException));
                goto ExitFalseClearBuffer;
            }
            catch
            {
                ArrayPool<byte>.Shared.Return(jsonBuffer);
                throw;
            }

        ExitFalseClearBuffer:
            ArrayPool<byte>.Shared.Return(jsonBuffer);
        ExitFalse:
            return false;
        }

        private static bool TryParseJwe(
            ReadOnlySpan<byte> utf8Token,
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
            var enc = header.Enc;
            if (enc.IsEmpty)
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

            if (!TryGetContentEncryptionKeys(header, utf8Token.Slice(encryptionKeySegment.Start, encryptionKeySegment.Length), encryptionAlgorithm, policy.DecryptionKeyProviders, out var keys))
            {
                error = TokenValidationError.EncryptionKeyNotFound();
                goto Error;
            }

            var rawInitializationVector = utf8Token.Slice(ivSegment.Start, ivSegment.Length);
            var rawCiphertext = utf8Token.Slice(ciphertextSegment.Start, ciphertextSegment.Length);
            var rawAuthenticationTag = utf8Token.Slice(authenticationTagSegment.Start, authenticationTagSegment.Length);

            int ciphertextBufferLength = Base64Url.GetArraySizeRequiredToDecode(ciphertextSegment.Length);
            byte[] ciphertextBuffer = ArrayPool<byte>.Shared.Rent(ciphertextBufferLength);
            Span<byte> decryptedBytes = new Span<byte>(ciphertextBuffer, 0, ciphertextBufferLength);
            if (TryDecryptToken(keys, rawHeader, rawCiphertext, rawInitializationVector, rawAuthenticationTag, encryptionAlgorithm, decryptedBytes, out int bytesWritten))
            {
                decryptedBytes = decryptedBytes.Slice(0, bytesWritten);
            }
            else
            {
                error = TokenValidationError.DecryptionFailed();
                goto Error;
            }

            PooledByteBufferWriter? decompressionsBufferWriter = null;
            if (header.TryGetHeaderParameter(JwtHeaderParameterNames.Zip.EncodedUtf8Bytes, out var zip))
            {
                if (!CompressionAlgorithm.TryParse(zip, out var compressionAlgorithm))
                {
                    error = TokenValidationError.InvalidHeader(JwtHeaderParameterNames.Zip.ToString());
                    goto Error;
                }

                var decompressor = compressionAlgorithm.Decompressor;
                decompressionsBufferWriter = new PooledByteBufferWriter(decryptedBytes.Length * 4);
                try
                {
                    decompressor.Decompress(decryptedBytes, decompressionsBufferWriter);

                    // There is no need to keep this buffer anymore
                    ArrayPool<byte>.Shared.Return(ciphertextBuffer, clearArray: true);
                }
                catch (Exception e)
                {
                    error = TokenValidationError.DecompressionFailed(e);
                    decompressionsBufferWriter.Dispose();
                    goto Error;
                }
            }

            Jwt jwe;
            ReadOnlyMemory<byte> rawValue;
            ReadOnlySpan<byte> rawSpan;
            byte[] rentedBuffer;
            if (decompressionsBufferWriter is null)
            {
                rawValue = new ReadOnlyMemory<byte>(ciphertextBuffer, 0, bytesWritten);
                rawSpan = decryptedBytes;
                rentedBuffer = ciphertextBuffer;
            }
            else
            {
                rawValue = decompressionsBufferWriter.WrittenMemory;
                rawSpan = decompressionsBufferWriter.WrittenSpan;
                rentedBuffer = decompressionsBufferWriter.Buffer;
            }

            if (policy.IgnoreNestedToken)
            {
                jwe = new Jwt(header, rawValue, rentedBuffer);
            }
            else
            {
                if (TryParse(rawSpan, policy, out Jwt nestedDocument))
                {
                    jwe = new Jwt(header, nestedDocument, rentedBuffer);
                }
                else
                {
                    if (nestedDocument.Error!.Status == TokenValidationStatus.MalformedToken && !policy.HasValidation)
                    {
                        // The decrypted payload is not a nested JWT
                        jwe = new Jwt(header, rawValue, rentedBuffer);
                    }
                    else
                    {
                        document = new Jwt(header, nestedDocument, nestedDocument.Error, rentedBuffer);
                        goto CompleteError;
                    }
                }
            }

            document = jwe;
            return true;

        Error:
            document = new Jwt(error);
        CompleteError:
            return false;
        }

        private static bool TryDecryptToken(
            List<SymmetricJwk> keys,
            ReadOnlySpan<byte> rawHeader,
            ReadOnlySpan<byte> rawCiphertext,
            ReadOnlySpan<byte> rawInitializationVector,
            ReadOnlySpan<byte> rawAuthenticationTag,
            EncryptionAlgorithm encryptionAlgorithm,
            Span<byte> decryptedBytes,
            out int bytesWritten)
        {
            int ciphertextLength = Base64Url.GetArraySizeRequiredToDecode(rawCiphertext.Length);
            int initializationVectorLength = Base64Url.GetArraySizeRequiredToDecode(rawInitializationVector.Length);
            int authenticationTagLength = Base64Url.GetArraySizeRequiredToDecode(rawAuthenticationTag.Length);
            int headerLength = rawHeader.Length;
            int bufferLength = ciphertextLength + headerLength + initializationVectorLength + authenticationTagLength;
            byte[]? arrayToReturn = null;
            Span<byte> buffer = bufferLength > Constants.MaxStackallocBytes
                ? (arrayToReturn = ArrayPool<byte>.Shared.Rent(bufferLength))
                : stackalloc byte[Constants.MaxStackallocBytes];

            Span<byte> ciphertext = buffer.Slice(0, ciphertextLength);
            Span<byte> header = buffer.Slice(ciphertextLength, headerLength);
            Span<byte> initializationVector = buffer.Slice(ciphertextLength + headerLength, initializationVectorLength);
            Span<byte> authenticationTag = buffer.Slice(ciphertextLength + headerLength + initializationVectorLength, authenticationTagLength);
            try
            {
                int ciphertextBytesWritten = Base64Url.DecodeUnsafe(rawCiphertext, ciphertext);
                Debug.Assert(ciphertext.Length == ciphertextBytesWritten);

                char[]? headerArrayToReturn = null;
                try
                {
                    int utf8HeaderLength = Utf8.GetMaxCharCount(header.Length);
                    Span<char> utf8Header = utf8HeaderLength > Constants.MaxStackallocChars
                        ? (headerArrayToReturn = ArrayPool<char>.Shared.Rent(utf8HeaderLength))
                        : stackalloc char[Constants.MaxStackallocChars];
                    
                    utf8HeaderLength = Utf8.GetChars(rawHeader, utf8Header);
                    Ascii.GetBytes(utf8Header.Slice(0, utf8HeaderLength), header);
                }
                finally
                {
                    if (headerArrayToReturn != null)
                    {
                        ArrayPool<char>.Shared.Return(headerArrayToReturn);
                    }
                }

                int ivBytesWritten = Base64Url.DecodeUnsafe(rawInitializationVector, initializationVector);
                Debug.Assert(initializationVector.Length == ivBytesWritten);

                int authenticationTagBytesWritten = Base64Url.DecodeUnsafe(rawAuthenticationTag, authenticationTag);
                Debug.Assert(authenticationTag.Length == authenticationTagBytesWritten);

                bytesWritten = 0;
                var decryptor = encryptionAlgorithm.Decryptor;

                for (int i = 0; i < keys.Count; i++)
                {
                    var key = keys[i];
                    if (decryptor.TryDecrypt(
                        key.K,
                        ciphertext,
                        header,
                        initializationVector,
                        authenticationTag,
                        decryptedBytes,
                        out bytesWritten))
                    {
                        return true;
                    }
                }

                return false;
            }
            finally
            {
                if (arrayToReturn != null)
                {
                    ArrayPool<byte>.Shared.Return(arrayToReturn);
                }
            }
        }

        private static bool TryGetContentEncryptionKeys(JwtHeaderDocument header, ReadOnlySpan<byte> rawEncryptedKey, EncryptionAlgorithm enc, IKeyProvider[] encryptionKeyProviders, [NotNullWhen(true)] out List<SymmetricJwk>? keys)
        {
            var alg = header.Alg;
            if (alg.IsEmpty)
            {
                keys = null;
                return false;
            }
            else
            {
                if (KeyManagementAlgorithm.TryParse(alg.GetRawValue().Span, out var algorithm))
                {
                    int decodedSize = Base64Url.GetArraySizeRequiredToDecode(rawEncryptedKey.Length);

                    byte[]? encryptedKeyToReturnToPool = null;
                    const int KeySizeThreshold = 72;
                    Span<byte> encryptedKey = decodedSize > KeySizeThreshold
                        ? encryptedKeyToReturnToPool = ArrayPool<byte>.Shared.Rent(decodedSize)
                        : stackalloc byte[KeySizeThreshold];

                    try
                    {
                        int bytesWritten = Base64Url.DecodeUnsafe(rawEncryptedKey, encryptedKey);
                        encryptedKey = encryptedKey.Slice(0, bytesWritten);

                        var keyUnwrappers = new List<(int, KeyUnwrapper)>(1);
                        int maxKeyUnwrapSize = 0;
                        for (int i = 0; i < encryptionKeyProviders.Length; i++)
                        {
                            var keySet = encryptionKeyProviders[i].GetKeys(header);
                            for (int j = 0; j < keySet.Length; j++)
                            {
                                var key = keySet[j];
                                if (key.CanUseForKeyWrapping(alg))
                                {
                                    if (key.TryGetKeyUnwrapper(enc, algorithm, out var keyUnwrapper))
                                    {
                                        int keyUnwrapSize = keyUnwrapper.GetKeyUnwrapSize(encryptedKey.Length);
                                        keyUnwrappers.Add((keyUnwrapSize, keyUnwrapper));
                                        if (maxKeyUnwrapSize < keyUnwrapSize)
                                        {
                                            maxKeyUnwrapSize = keyUnwrapSize;
                                        }
                                    }
                                }
                            }
                        }

                        keys = new List<SymmetricJwk>(1);
                        const int UnwrappedKeySizeThreshold = 64;
                        Span<byte> unwrappedKey = stackalloc byte[UnwrappedKeySizeThreshold];
                        for (int i = 0; i < keyUnwrappers.Count; i++)
                        {
                            var kpv = keyUnwrappers[i];
                            var temporaryUnwrappedKey = unwrappedKey.Length != kpv.Item1 ? unwrappedKey.Slice(0, kpv.Item1) : unwrappedKey;
                            if (kpv.Item2.TryUnwrapKey(encryptedKey, temporaryUnwrappedKey, header, out int keyUnwrappedBytesWritten))
                            {
                                var jwk = SymmetricJwk.FromByteArray(unwrappedKey.Slice(0, keyUnwrappedBytesWritten).ToArray(), false);
                                keys.Add(jwk);
                            }
                        }
                    }
                    finally
                    {
                        if (encryptedKeyToReturnToPool != null)
                        {
                            ArrayPool<byte>.Shared.Return(encryptedKeyToReturnToPool, true);
                        }
                    }
                }
                else
                {
                    keys = null;
                    return false;
                }
            }

            return keys.Count != 0;
        }

        /// <inheritdoc />
        public void Dispose()
        {
            _rawValue = ReadOnlyMemory<byte>.Empty;
            _payload?.Dispose();
            _header.Dispose();
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