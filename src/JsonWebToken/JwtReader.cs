// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>
    /// Reads and validates a JWT.
    /// </summary>
    public sealed partial class JwtReader : IDisposable
    {
        private readonly IKeyProvider[] _encryptionKeyProviders;
        private readonly JwtHeaderCache _headerCache;
        private readonly KeyWrapperFactory _keyWrapFactory;
        private readonly SignerFactory _signatureFactory;
        private readonly AuthenticatedEncryptorFactory _authenticatedEncryptionFactory;
        private readonly bool _disposeFactories;

        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of <see cref="JwtReader"/>.
        /// </summary>
        /// <param name="encryptionKeyProviders"></param>
        /// <param name="signerFactory"></param>
        /// <param name="keyWrapperFactory"></param>
        /// <param name="authenticatedEncryptorFactory"></param>
        public JwtReader(
            ICollection<IKeyProvider> encryptionKeyProviders,
            SignerFactory signerFactory,
            KeyWrapperFactory keyWrapperFactory,
            AuthenticatedEncryptorFactory authenticatedEncryptorFactory)
            : this(encryptionKeyProviders, signerFactory, keyWrapperFactory, authenticatedEncryptorFactory, null)
        {
        }

        /// <summary>
        /// Initializes a new instance of <see cref="JwtReader"/>.
        /// </summary>
        /// <param name="encryptionKeyProviders"></param>
        /// <param name="signerFactory"></param>
        /// <param name="keyWrapperFactory"></param>
        /// <param name="authenticatedEncryptorFactory"></param>
        /// <param name="headerCache"></param>
        public JwtReader(
                  ICollection<IKeyProvider> encryptionKeyProviders,
                  SignerFactory signerFactory,
                  KeyWrapperFactory keyWrapperFactory,
                  AuthenticatedEncryptorFactory authenticatedEncryptorFactory,
                  JwtHeaderCache headerCache)
        {
            if (encryptionKeyProviders == null)
            {
                Errors.ThrowArgumentNullException(ExceptionArgument.encryptionKeyProviders);
            }

            if (signerFactory == null)
            {
                Errors.ThrowArgumentNullException(ExceptionArgument.signerFactory);
            }

            if (keyWrapperFactory == null)
            {
                Errors.ThrowArgumentNullException(ExceptionArgument.keyWrapperFactory);
            }

            if (authenticatedEncryptorFactory == null)
            {
                Errors.ThrowArgumentNullException(ExceptionArgument.authenticatedEncryptorFactory);
            }

            _encryptionKeyProviders = encryptionKeyProviders.Where(p => p != null).ToArray();
            _signatureFactory = signerFactory;
            _keyWrapFactory = keyWrapperFactory;
            _authenticatedEncryptionFactory = authenticatedEncryptorFactory;
            _headerCache = headerCache ?? new JwtHeaderCache();
        }

        /// <summary>
        /// Initializes a new instance of <see cref="JwtReader"/>.
        /// </summary>
        /// <param name="encryptionKeyProviders"></param>
        public JwtReader(ICollection<IKeyProvider> encryptionKeyProviders)
            : this(encryptionKeyProviders, new DefaultSignerFactory(), new DefaultKeyWrapperFactory(), new DefaultAuthenticatedEncryptorFactory())
        {
            _disposeFactories = true;
        }

        /// <summary>
        /// Initializes a new instance of <see cref="JwtReader"/>.
        /// </summary>
        /// <param name="keys"></param>
        public JwtReader(IList<Jwk> keys)
           : this(new Jwks(keys))
        {
        }

        /// <summary>
        /// Initializes a new instance of <see cref="JwtReader"/>.
        /// </summary>
        /// <param name="keys"></param>
        public JwtReader(params Jwk[] keys)
           : this(new Jwks(keys))
        {
        }

        /// <summary>
        /// Initializes a new instance of <see cref="JwtReader"/>.
        /// </summary>
        /// <param name="encryptionKeyProvider"></param>
        public JwtReader(IKeyProvider encryptionKeyProvider)
            : this(new[] { encryptionKeyProvider })
        {
        }

        /// <summary>
        /// Initializes a new instance of <see cref="JwtReader"/>.
        /// </summary>
        /// <param name="encryptionKeys"></param>
        public JwtReader(Jwks encryptionKeys)
            : this(new StaticKeyProvider(encryptionKeys))
        {
        }

        /// <summary>
        /// Initializes a new instance of <see cref="JwtReader"/>.
        /// </summary>
        /// <param name="encryptionKey"></param>
        public JwtReader(Jwk encryptionKey)
            : this(new Jwks(encryptionKey))
        {
        }

        /// <summary>
        /// Initializes a new instance of <see cref="JwtReader"/>.
        /// </summary>
        public JwtReader()
            : this(Array.Empty<IKeyProvider>())
        {
        }

        /// <summary>
        /// Defines whether the header will be cached. Default is <c>true</c>.
        /// </summary>
        public bool EnableHeaderCaching { get; set; } = true;

        /// <summary>
        /// Reads and validates a JWT encoded as a JWS or JWE in compact serialized format.
        /// </summary>
        /// <param name="token">The JWT encoded as JWE or JWS</param>
        /// <param name="policy">The validation policy.</param>
        public TokenValidationResult TryReadToken(string token, TokenValidationPolicy policy)
        {
            if (token == null)
            {
                Errors.ThrowArgumentNullException(ExceptionArgument.token);
            }

            if (policy == null)
            {
                Errors.ThrowArgumentNullException(ExceptionArgument.policy);
            }

            return TryReadToken(token.AsSpan(), policy);
        }

        /// <summary>
        /// Reads and validates a JWT encoded as a JWS or JWE in compact serialized format.
        /// </summary>
        /// <param name="utf8Token">The JWT encoded as JWE or JWS.</param>
        /// <param name="policy">The validation policy.</param>
        public TokenValidationResult TryReadToken(in ReadOnlySequence<byte> utf8Token, TokenValidationPolicy policy)
        {
            if (utf8Token.IsSingleSegment)
            {
                return TryReadToken(utf8Token.First.Span, policy);
            }

            return TryReadToken(utf8Token.ToArray(), policy);
        }

        /// <summary>
        /// Reads and validates a JWT encoded as a JWS or JWE in compact serialized format.
        /// </summary>
        /// <param name="token">The JWT encoded as JWE or JWS</param>
        /// <param name="policy">The validation policy.</param>
        public TokenValidationResult TryReadToken(ReadOnlySpan<char> token, TokenValidationPolicy policy)
        {
            if (policy == null)
            {
                Errors.ThrowArgumentNullException(ExceptionArgument.policy);
            }

            if (_disposed)
            {
                Errors.ThrowObjectDisposed(typeof(JwtReader));
            }

            if (token.IsEmpty)
            {
                return TokenValidationResult.MalformedToken();
            }

            int length = token.Length;
            if (length > policy.MaximumTokenSizeInBytes)
            {
                return TokenValidationResult.MalformedToken();
            }

            byte[] utf8ArrayToReturnToPool = null;
            var utf8Token = length <= Constants.MaxStackallocBytes
                  ? stackalloc byte[length]
                  : (utf8ArrayToReturnToPool = ArrayPool<byte>.Shared.Rent(length)).AsSpan(0, length);
            try
            {
#if !NETSTANDARD2_0
                Encoding.UTF8.GetBytes(token, utf8Token);
#else
                EncodingHelper.GetUtf8Bytes(token, utf8Token);
#endif
                return TryReadToken(utf8Token, policy);
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
        /// Reads and validates a JWT encoded as a JWS or JWE in compact serialized format.
        /// </summary>
        /// <param name="utf8Token">The JWT encoded as JWE or JWS.</param>
        /// <param name="policy">The validation policy.</param>
        public unsafe TokenValidationResult TryReadToken(ReadOnlySpan<byte> utf8Token, TokenValidationPolicy policy)
        {
            if (policy == null)
            {
                Errors.ThrowArgumentNullException(ExceptionArgument.policy);
            }

            if (_disposed)
            {
                Errors.ThrowObjectDisposed(typeof(JwtReader));
            }

            string malformedMessage = null;
            Exception malformedException = null;
            if (utf8Token.IsEmpty)
            {
                goto Malformed;
            }

            if (utf8Token.Length > policy.MaximumTokenSizeInBytes)
            {
                goto Malformed;
            }

            var pSegments = stackalloc TokenSegment[Constants.JweSegmentCount];
            var segmentCount = Tokenizer.Tokenize(utf8Token, pSegments);
            if (segmentCount < Constants.JwsSegmentCount)
            {
                goto Malformed;
            }

            var segments = new ReadOnlySpan<TokenSegment>(pSegments, segmentCount);
            var headerSegment = segments[0];
            if (headerSegment.IsEmpty)
            {
                goto Malformed;
            }

            JwtHeader header;
            var rawHeader = utf8Token.Slice(0, headerSegment.Length);
            try
            {
                if (EnableHeaderCaching)
                {
                    if (!_headerCache.TryGetHeader(rawHeader, out header))
                    {
                        header = GetJsonHeader(rawHeader);
                        _headerCache.AddHeader(rawHeader, header);
                    }
                }
                else
                {
                    header = GetJsonHeader(rawHeader);
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
            var headerValidationResult = policy.TryValidate(new CriticalHeaderValidationContext(header));
            if (!headerValidationResult.Succedeed)
            {
                return headerValidationResult;
            }

            if (segments.Length == Constants.JwsSegmentCount)
            {
                return TryReadJws(utf8Token, policy, segments[0], segments[1], segments[2], header);
            }
            else if (segments.Length == Constants.JweSegmentCount)
            {
                return TryReadJwe(utf8Token, policy, rawHeader, segments[1], segments[2], segments[3], segments[4], header);
            }

        Malformed:
            return TokenValidationResult.MalformedToken(malformedMessage, malformedException);
        }

        private TokenValidationResult TryReadJwe(
            ReadOnlySpan<byte> utf8Buffer,
            TokenValidationPolicy policy,
            ReadOnlySpan<byte> rawHeader,
            TokenSegment encryptionKeySegment,
            TokenSegment ivSegment,
            TokenSegment ciphertextSegment,
            TokenSegment authenticationTagSegment,
            JwtHeader header)
        {
            var enc = header.EncryptionAlgorithm;
            if (enc is null)
            {
                return TokenValidationResult.MissingEncryptionAlgorithm();
            }

            var keys = GetContentEncryptionKeys(header, utf8Buffer.Slice(encryptionKeySegment.Start, encryptionKeySegment.Length), enc);
            if (keys.Count == 0)
            {
                return TokenValidationResult.EncryptionKeyNotFound();
            }

            var rawInitializationVector = utf8Buffer.Slice(ivSegment.Start, ivSegment.Length);
            var rawCiphertext = utf8Buffer.Slice(ciphertextSegment.Start, ciphertextSegment.Length);
            var rawAuthenticationTag = utf8Buffer.Slice(authenticationTagSegment.Start, authenticationTagSegment.Length);

            int decryptedLength = Base64Url.GetArraySizeRequiredToDecode(rawCiphertext.Length);
            byte[] decryptedArrayToReturnToPool = null;
            var decryptedBytes = decryptedLength <= Constants.MaxStackallocBytes
                  ? stackalloc byte[decryptedLength]
                  : (decryptedArrayToReturnToPool = ArrayPool<byte>.Shared.Rent(decryptedLength)).AsSpan(0, decryptedLength);

            try
            {
                Jwk decryptionKey = null;
                bool decrypted = false;
                for (int i = 0; i < keys.Count; i++)
                {
                    decryptionKey = keys[i];
                    if (TryDecryptToken(rawHeader, rawCiphertext, rawInitializationVector, rawAuthenticationTag, enc, decryptionKey, decryptedBytes, out int bytesWritten))
                    {
                        decryptedBytes = decryptedBytes.Slice(0, bytesWritten);
                        decrypted = true;
                        break;
                    }
                }

                if (!decrypted)
                {
                    return TokenValidationResult.DecryptionFailed();
                }

                bool compressed;
                ReadOnlySequence<byte> decompressedBytes = default;
                var zip = (CompressionAlgorithm)header.Zip;
                if (zip is null)
                {
                    compressed = false;
                }
                else
                {
                    Compressor compressor = zip.Compressor;
                    if (compressor == null)
                    {
                        return TokenValidationResult.InvalidHeader(HeaderParameters.ZipUtf8);
                    }

                    try
                    {
                        compressed = true;
                        decompressedBytes = compressor.Decompress(decryptedBytes);
                    }
                    catch (Exception e)
                    {
                        return TokenValidationResult.DecompressionFailed(e);
                    }
                }

                Jwt jwe;
                var cty = header.Cty;
                if (!cty.IsEmpty && ContentTypeValues.JwtUtf8.SequenceEqual(cty))
                {
                    var decryptionResult = compressed
                        ? TryReadToken(decompressedBytes, policy)
                        : TryReadToken(decryptedBytes, policy);
                    if (!decryptionResult.Succedeed)
                    {
                        return decryptionResult;
                    }

                    var decryptedJwt = decryptionResult.Token;
                    jwe = new Jwt(header, decryptedJwt, decryptionKey);
                }
                else
                {
                    // The decrypted payload is not a nested JWT
                    jwe = new Jwt(header, compressed ? decompressedBytes.ToArray() : decryptedBytes.ToArray(), decryptionKey);
                }

                return TokenValidationResult.Success(jwe);
            }
            finally
            {
                if (decryptedArrayToReturnToPool != null)
                {
                    ArrayPool<byte>.Shared.Return(decryptedArrayToReturnToPool);
                }
            }
        }

        private TokenValidationResult TryReadJws(
            ReadOnlySpan<byte> utf8Buffer,
            TokenValidationPolicy policy,
            TokenSegment headerSegment,
            TokenSegment payloadSegment,
            TokenSegment signatureSegment,
            JwtHeader header)
        {
            var rawPayload = utf8Buffer.Slice(payloadSegment.Start, payloadSegment.Length);
            Exception malformedException;
            JwtPayload payload;
            try
            {
                payload = GetJsonPayload(rawPayload);
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

            Jwt jws = new Jwt(header, payload);
            if (policy.SignatureValidation != null)
            {
                var result = TryValidateSignature(policy.SignatureValidation, jws, utf8Buffer.Slice(headerSegment.Start, headerSegment.Length + payloadSegment.Length + 1), utf8Buffer.Slice(signatureSegment.Start, signatureSegment.Length));
                if (!result.Succedeed)
                {
                    return result;
                }
            }

            if (policy.HasValidation)
            {
                return policy.TryValidate(new TokenValidationContext(jws));
            }

            return TokenValidationResult.Success(jws);
        Malformed:
            return TokenValidationResult.MalformedToken(exception: malformedException);
        }

        private static JwtPayload GetJsonPayload(ReadOnlySpan<byte> data)
        {
            int bufferLength = Base64Url.GetArraySizeRequiredToDecode(data.Length);
            byte[] base64UrlArrayToReturnToPool = null;
            var buffer = bufferLength <= Constants.MaxStackallocBytes
              ? stackalloc byte[bufferLength]
              : (base64UrlArrayToReturnToPool = ArrayPool<byte>.Shared.Rent(bufferLength)).AsSpan(0, bufferLength);
            try
            {
                Base64Url.Decode(data, buffer);
                return JsonPayloadParser.ParsePayload(buffer);
            }
            finally
            {
                if (base64UrlArrayToReturnToPool != null)
                {
                    ArrayPool<byte>.Shared.Return(base64UrlArrayToReturnToPool);
                }
            }
        }

        private static JwtHeader GetJsonHeader(ReadOnlySpan<byte> data)
        {
            int base64UrlLength = Base64Url.GetArraySizeRequiredToDecode(data.Length);
            byte[] base64UrlArrayToReturnToPool = null;
            var buffer = base64UrlLength <= Constants.MaxStackallocBytes
              ? stackalloc byte[base64UrlLength]
              : (base64UrlArrayToReturnToPool = ArrayPool<byte>.Shared.Rent(base64UrlLength)).AsSpan(0, base64UrlLength);
            try
            {
                Base64Url.Decode(data, buffer);
                return JsonHeaderParser.ParseHeader(buffer);
            }
            finally
            {
                if (base64UrlArrayToReturnToPool != null)
                {
                    ArrayPool<byte>.Shared.Return(base64UrlArrayToReturnToPool);
                }
            }
        }

        private bool TryDecryptToken(
            ReadOnlySpan<byte> rawHeader,
            ReadOnlySpan<byte> rawCiphertext,
            ReadOnlySpan<byte> rawInitializationVector,
            ReadOnlySpan<byte> rawAuthenticationTag,
            EncryptionAlgorithm encryptionAlgorithm,
            Jwk key,
            Span<byte> decryptedBytes,
            out int bytesWritten)
        {
            var decryptor = _authenticatedEncryptionFactory.Create(key, encryptionAlgorithm);
            if (decryptor == null)
            {
                return Errors.TryWriteError(out bytesWritten);
            }

            int ciphertextLength = Base64Url.GetArraySizeRequiredToDecode(rawCiphertext.Length);
            int headerLength = rawHeader.Length;
            int initializationVectorLength = Base64Url.GetArraySizeRequiredToDecode(rawInitializationVector.Length);
            int authenticationTagLength = Base64Url.GetArraySizeRequiredToDecode(rawAuthenticationTag.Length);
            int bufferLength = ciphertextLength + headerLength + initializationVectorLength + authenticationTagLength;
            byte[] arrayToReturn = null;
            Span<byte> buffer = bufferLength < Constants.MaxStackallocBytes
                ? stackalloc byte[bufferLength]
                : (arrayToReturn = ArrayPool<byte>.Shared.Rent(bufferLength)).AsSpan(0, bufferLength);

            Span<byte> ciphertext = buffer.Slice(0, ciphertextLength);
            Span<byte> header = buffer.Slice(ciphertextLength, headerLength);
            Span<byte> initializationVector = buffer.Slice(ciphertextLength + headerLength, initializationVectorLength);
            Span<byte> authenticationTag = buffer.Slice(ciphertextLength + headerLength + initializationVectorLength, authenticationTagLength);
            try
            {
                Base64Url.Decode(rawCiphertext, ciphertext, out int ciphertextBytesConsumed, out int ciphertextBytesWritten);
                Debug.Assert(ciphertext.Length == ciphertextBytesWritten);

#if !NETSTANDARD2_0
                char[] headerArrayToReturn = null;
                try
                {
                    Span<char> utf8Header = header.Length < Constants.MaxStackallocBytes
                        ? stackalloc char[header.Length]
                        : (headerArrayToReturn = ArrayPool<char>.Shared.Rent(header.Length)).AsSpan(0, header.Length);

                    Encoding.UTF8.GetChars(rawHeader, utf8Header);
                    Encoding.ASCII.GetBytes(utf8Header, header);
                }
                finally
                {
                    if (headerArrayToReturn != null)
                    {
                        ArrayPool<char>.Shared.Return(headerArrayToReturn);
                    }
                }
#else
                EncodingHelper.GetAsciiBytes(rawHeader, header);
#endif
                Base64Url.Decode(rawInitializationVector, initializationVector, out int ivBytesConsumed, out int ivBytesWritten);
                Debug.Assert(initializationVector.Length == ivBytesWritten);

                Base64Url.Decode(rawAuthenticationTag, authenticationTag, out int authenticationTagBytesConsumed, out int authenticationTagBytesWritten);
                Debug.Assert(authenticationTag.Length == authenticationTagBytesWritten);

                if (!decryptor.TryDecrypt(
                    ciphertext,
                    header,
                    initializationVector,
                    authenticationTag,
                    decryptedBytes,
                    out bytesWritten))
                {
                    return false;
                }
            }
            finally
            {
                if (arrayToReturn != null)
                {
                    ArrayPool<byte>.Shared.Return(arrayToReturn);
                }
            }

            return decryptedBytes != null;
        }

        private List<Jwk> GetContentEncryptionKeys(JwtHeader header, ReadOnlySpan<byte> rawEncryptedKey, EncryptionAlgorithm enc)
        {
            var alg = header.KeyManagementAlgorithm;
            var keys = ResolveDecryptionKey(header, alg);
            var keyManamagementAlg = alg;
            if (keyManamagementAlg == KeyManagementAlgorithm.Direct)
            {
                return keys;
            }

            Span<byte> encryptedKey = stackalloc byte[Base64Url.GetArraySizeRequiredToDecode(rawEncryptedKey.Length)];
            var operationResult = Base64Url.Decode(rawEncryptedKey, encryptedKey, out _, out _);
            Debug.Assert(operationResult == OperationStatus.Done);

            var unwrappedKeys = new List<Jwk>(1);
            for (int i = 0; i < keys.Count; i++)
            {
                var key = keys[i];
                KeyWrapper kwp = _keyWrapFactory.Create(key, enc, keyManamagementAlg);
                if (kwp != null)
                {
                    Span<byte> unwrappedKey = stackalloc byte[kwp.GetKeyUnwrapSize(encryptedKey.Length)];
                    if (kwp.TryUnwrapKey(encryptedKey, unwrappedKey, header, out int keyWrappedBytesWritten))
                    {
                        unwrappedKeys.Add(SymmetricJwk.FromSpan(unwrappedKey.Slice(0, keyWrappedBytesWritten)));
                    }
                }
            }

            return unwrappedKeys;
        }

        private List<Jwk> ResolveDecryptionKey(JwtHeader header, KeyManagementAlgorithm alg)
        {
            var keys = new List<Jwk>(1);
            for (int i = 0; i < _encryptionKeyProviders.Length; i++)
            {
                var keySet = _encryptionKeyProviders[i].GetKeys(header);
                for (int j = 0; j < keySet.Length; j++)
                {
                    var key = keySet[j];
                    if (key.CanUseForKeyWrapping(alg))
                    {
                        keys.Add(key);
                    }
                }
            }

            return keys;
        }

        private TokenValidationResult TryValidateSignature(SignatureValidationContext signatureValidationContext, Jwt jwt, ReadOnlySpan<byte> contentBytes, ReadOnlySpan<byte> signatureSegment)
        {
            if (contentBytes.Length == 0 && signatureSegment.Length == 0)
            {
                // This is not a JWS
                goto Success;
            }

            if (signatureSegment.IsEmpty)
            {
                if (signatureValidationContext.SupportUnsecure && jwt.SignatureAlgorithm == SignatureAlgorithm.None)
                {
                    goto Success;
                }

                return TokenValidationResult.MissingSignature(jwt);
            }

            try
            {
                int signatureBytesLength = Base64Url.GetArraySizeRequiredToDecode(signatureSegment.Length);
                Span<byte> signatureBytes = stackalloc byte[signatureBytesLength];
                Base64Url.Decode(signatureSegment, signatureBytes, out int byteConsumed, out int bytesWritten);
                Debug.Assert(bytesWritten == signatureBytes.Length);
                bool keysTried = false;

                var keySet = signatureValidationContext.KeyProvider.GetKeys(jwt.Header);
                if (keySet != null)
                {
                    for (int i = 0; i < keySet.Length; i++)
                    {
                        var key = keySet[i];
                        if (key.CanUseForSignature(jwt.Header.SignatureAlgorithm))
                        {
                            var alg = signatureValidationContext.Algorithm ?? key.SignatureAlgorithm;
                            if (TryValidateSignature(contentBytes, signatureBytes, key, alg))
                            {
                                jwt.SigningKey = key;
                                goto Success;
                            }

                            keysTried = true;
                        }
                    }
                }

                if (keysTried)
                {
                    return TokenValidationResult.InvalidSignature(jwt);
                }

                return TokenValidationResult.SignatureKeyNotFound(jwt);
            }
            catch (FormatException e)
            {
                return TokenValidationResult.MalformedSignature(jwt, e);
            }

        Success:
            return TokenValidationResult.Success(jwt);
        }

        private bool TryValidateSignature(ReadOnlySpan<byte> contentBytes, ReadOnlySpan<byte> signature, Jwk key, SignatureAlgorithm algorithm)
        {
            var signer = _signatureFactory.CreateForValidation(key, algorithm);
            if (signer == null)
            {
                return false;
            }

            return signer.Verify(contentBytes, signature);
        }

        /// <summary>
        /// Releases managed reources.
        /// </summary>
        public void Dispose()
        {
            if (!_disposed && _disposeFactories)
            {
                _signatureFactory.Dispose();
                _keyWrapFactory.Dispose();
                _authenticatedEncryptionFactory.Dispose();
                _disposed = true;
            }
        }
    }
}