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
    public sealed class JwtReader : IDisposable
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
                throw new ArgumentNullException(nameof(encryptionKeyProviders));
            }

            _encryptionKeyProviders = encryptionKeyProviders.ToArray();
            _signatureFactory = signerFactory ?? throw new ArgumentNullException(nameof(signerFactory));
            _keyWrapFactory = keyWrapperFactory ?? throw new ArgumentNullException(nameof(keyWrapperFactory));
            _authenticatedEncryptionFactory = authenticatedEncryptorFactory ?? throw new ArgumentNullException(nameof(authenticatedEncryptorFactory));
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
            : this(new[] { encryptionKeyProvider ?? throw new ArgumentNullException(nameof(encryptionKeyProvider)) })
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
                throw new ArgumentNullException(nameof(token));
            }

            if (policy == null)
            {
                throw new ArgumentNullException(nameof(policy));
            }

            return TryReadToken(token.AsSpan(), policy);
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
                throw new ArgumentNullException(nameof(policy));
            }

            if (_disposed)
            {
                Errors.ThrowObjectDisposed(GetType());
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
        public TokenValidationResult TryReadToken(in ReadOnlySequence<byte> utf8Token, TokenValidationPolicy policy)
        {
            if (utf8Token.IsSingleSegment)
            {
                return TryReadToken(utf8Token.First.Span, policy);
            }

            return TryReadTokenMultiSegment(utf8Token, policy);
        }

        private TokenValidationResult TryReadTokenMultiSegment(in ReadOnlySequence<byte> utf8TokenSequence, TokenValidationPolicy policy)
        {
            // TODO : Read directly from the ReadOnlySequence withouy copy
            var sequenceLength = (int)utf8TokenSequence.Length;
            byte[] arrayToReturnToPool = null;
            var utf8Token = sequenceLength <= Constants.MaxStackallocBytes
                          ? stackalloc byte[sequenceLength]
                          : (arrayToReturnToPool = ArrayPool<byte>.Shared.Rent(sequenceLength)).AsSpan(0, sequenceLength);

            try
            {
                utf8TokenSequence.CopyTo(utf8Token);
                return TryReadToken(utf8Token, policy);
            }
            finally
            {
                if (arrayToReturnToPool != null)
                {
                    ArrayPool<byte>.Shared.Return(arrayToReturnToPool);
                }
            }
        }

        /// <summary>
        /// Reads and validates a JWT encoded as a JWS or JWE in compact serialized format.
        /// </summary>
        /// <param name="utf8Token">The JWT encoded as JWE or JWS.</param>
        /// <param name="policy">The validation policy.</param>
        public TokenValidationResult TryReadToken(ReadOnlySpan<byte> utf8Token, TokenValidationPolicy policy)
        {
            if (policy == null)
            {
                throw new ArgumentNullException(nameof(policy));
            }

            if (_disposed)
            {
                Errors.ThrowObjectDisposed(GetType());
            }

            if (utf8Token.IsEmpty)
            {
                return TokenValidationResult.MalformedToken();
            }

            if (utf8Token.Length > policy.MaximumTokenSizeInBytes)
            {
                return TokenValidationResult.MalformedToken();
            }

            Span<TokenSegment> segments = stackalloc TokenSegment[Constants.JweSegmentCount];
            var segmentCount = Tokenizer.Tokenize(utf8Token, segments);
            if (segmentCount < Constants.JwsSegmentCount)
            {
                return TokenValidationResult.MalformedToken();
            }

            var headerSegment = segments[0];
            if (headerSegment.IsEmpty)
            {
                return TokenValidationResult.MalformedToken();
            }

            JwtHeader header;
            var rawHeader = utf8Token.Slice(headerSegment.Start, headerSegment.Length);
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
                return TokenValidationResult.MalformedToken(formatException);
            }
            catch (JsonReaderException readerException)
            {
                return TokenValidationResult.MalformedToken(readerException);
            }

            var headerValidationResult = policy.TryValidate(new CriticalHeaderValidationContext(header));
            if (!headerValidationResult.Succedeed)
            {
                return headerValidationResult;
            }

            if (segmentCount == Constants.JwsSegmentCount)
            {
                return TryReadJws(utf8Token, policy, segments, header);
            }
            else if (segmentCount == Constants.JweSegmentCount)
            {
                return TryReadJwe(utf8Token, policy, segments, header, rawHeader);
            }

            return TokenValidationResult.MalformedToken();
        }

        private TokenValidationResult TryReadJwe(
            ReadOnlySpan<byte> utf8Buffer,
            TokenValidationPolicy policy,
            Span<TokenSegment> segments,
            JwtHeader header,
            ReadOnlySpan<byte> rawHeader)
        {
            var enc = (EncryptionAlgorithm)header.Enc;
            if (enc is null)
            {
                return TokenValidationResult.MissingEncryptionAlgorithm();
            }

            var encryptionKeySegment = segments[1];
            var keys = GetContentEncryptionKeys(header, utf8Buffer.Slice(encryptionKeySegment.Start, encryptionKeySegment.Length), enc);
            if (keys.Count == 0)
            {
                return TokenValidationResult.EncryptionKeyNotFound();
            }

            var ivSegment = segments[2];
            var rawInitializationVector = utf8Buffer.Slice(ivSegment.Start, ivSegment.Length);

            var ciphertextSegment = segments[3];
            var rawCiphertext = utf8Buffer.Slice(ciphertextSegment.Start, ciphertextSegment.Length);

            var authenticationTagSegment = segments[4];
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
                if (!(zip is null))
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
                else
                {
                    compressed = false;
                }

                Jwt jwe;
                var cty = header.Cty;
                if (cty != null && ContentTypeValues.JwtUtf8.SequenceEqual(cty.AsSpan()))
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
            Span<TokenSegment> segments,
            JwtHeader header)
        {
            var payloadSegment = segments[1];
            var rawPayload = utf8Buffer.Slice(payloadSegment.Start, payloadSegment.Length);
            JwtPayload payload;
            try
            {
                payload = GetJsonPayload(rawPayload);
            }
            catch (FormatException formatException)
            {
                return TokenValidationResult.MalformedToken(formatException);
            }
            catch (JsonReaderException readerException)
            {
                return TokenValidationResult.MalformedToken(readerException);
            }

            Jwt jws = new Jwt(header, payload);

            if (policy.SignatureValidation != null)
            {
                var headerSegment = segments[0];
                var signatureSegment = segments[2];
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
                Base64Url.Base64UrlDecode(data, buffer);
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
                Base64Url.Base64UrlDecode(data, buffer);
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
                Base64Url.Base64UrlDecode(rawCiphertext, ciphertext, out int ciphertextBytesConsumed, out int ciphertextBytesWritten);
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
                Base64Url.Base64UrlDecode(rawInitializationVector, initializationVector, out int ivBytesConsumed, out int ivBytesWritten);
                Debug.Assert(initializationVector.Length == ivBytesWritten);

                Base64Url.Base64UrlDecode(rawAuthenticationTag, authenticationTag, out int authenticationTagBytesConsumed, out int authenticationTagBytesWritten);
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
            var alg = (KeyManagementAlgorithm)header.Alg;
            var keys = ResolveDecryptionKey(header);
            if (alg == KeyManagementAlgorithm.Direct)
            {
                return keys;
            }

            Span<byte> encryptedKey = stackalloc byte[Base64Url.GetArraySizeRequiredToDecode(rawEncryptedKey.Length)];
            var operationResult = Base64Url.Base64UrlDecode(rawEncryptedKey, encryptedKey, out _, out _);
            Debug.Assert(operationResult == OperationStatus.Done);

            var unwrappedKeys = new List<Jwk>(1);
            for (int i = 0; i < keys.Count; i++)
            {
                var key = keys[i];
                KeyWrapper kwp = _keyWrapFactory.Create(key, enc, alg);
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

        private List<Jwk> ResolveDecryptionKey(JwtHeader header)
        {
            var alg = header.Alg;

            var keys = new List<Jwk>(1);
            for (int i = 0; i < _encryptionKeyProviders.Length; i++)
            {
                var keySet = _encryptionKeyProviders[i].GetKeys(header);

                for (int j = 0; j < keySet.Length; j++)
                {
                    var key = keySet[j];
                    if ((key.Use == null || JwkUseNames.Enc.SequenceEqual(key.Use)) &&
                        (key.Alg == null || key.Alg.AsSpan().SequenceEqual(alg)))
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
                return TokenValidationResult.Success(jwt);
            }

            if (signatureSegment.IsEmpty)
            {
                if (signatureValidationContext.SupportUnsecure && jwt.SignatureAlgorithm == SignatureAlgorithm.None)
                {
                    return TokenValidationResult.Success(jwt);
                }

                return TokenValidationResult.MissingSignature(jwt);
            }

            int signatureBytesLength;
            try
            {
                signatureBytesLength = Base64Url.GetArraySizeRequiredToDecode(signatureSegment.Length);
            }
            catch (FormatException e)
            {
                return TokenValidationResult.MalformedSignature(jwt, e);
            }

            Span<byte> signatureBytes = stackalloc byte[signatureBytesLength];
            try
            {
                Base64Url.Base64UrlDecode(signatureSegment, signatureBytes, out int byteConsumed, out int bytesWritten);
                Debug.Assert(bytesWritten == signatureBytes.Length);
            }
            catch (FormatException e)
            {
                return TokenValidationResult.MalformedSignature(jwt, e);
            }

            bool keysTried = false;

            var keySet = signatureValidationContext.KeyProvider.GetKeys(jwt.Header);
            if (keySet != null)
            {
                for (int j = 0; j < keySet.Length; j++)
                {
                    var key = keySet[j];
                    if ((key.Use == null || JwkUseNames.Sig.SequenceEqual(key.Use)) &&
                        (key.Alg == null || key.Alg.AsSpan().SequenceEqual(jwt.Header.Alg)))
                    {
                        var alg = signatureValidationContext.Algorithm ?? key.Alg;
                        if (TryValidateSignature(contentBytes, signatureBytes, key, alg))
                        {
                            jwt.SigningKey = key;
                            return TokenValidationResult.Success(jwt);
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

        private bool TryValidateSignature(ReadOnlySpan<byte> contentBytes, ReadOnlySpan<byte> signature, Jwk key, SignatureAlgorithm algorithm)
        {
            var signer = _signatureFactory.Create(key, algorithm, willCreateSignatures: false);
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