// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using Newtonsoft.Json;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace JsonWebToken
{
    /// <summary>
    /// Reads and validates a JWT.
    /// </summary>
    public sealed class JwtReader : IDisposable
    {
        private const byte dot = 0x2E;

        private readonly IKeyProvider[] _encryptionKeyProviders;
        private readonly JwtHeaderCache _headerCache;
        private readonly KeyWrapperFactory _keyWrapFactory;
        private readonly SignerFactory _signatureFactory;
        private readonly AuthenticatedEncryptorFactory _authenticatedEncryptionFactory;
        private readonly bool _disposeFactories;

        private bool _disposed;

        public JwtReader(
            ICollection<IKeyProvider> encryptionKeyProviders,
            SignerFactory signerFactory,
            KeyWrapperFactory keyWrapperFactory,
            AuthenticatedEncryptorFactory authenticatedEncryptorFactory)
            : this(encryptionKeyProviders, signerFactory, keyWrapperFactory, authenticatedEncryptorFactory, null)
        {
        }

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

        public JwtReader(ICollection<IKeyProvider> encryptionKeyProviders)
            : this(encryptionKeyProviders, new DefaultSignerFactory(), new DefaultKeyWrapperFactory(), new DefaultAuthenticatedEncryptorFactory())
        {
            _disposeFactories = true;
        }

        public JwtReader(IList<Jwk> keys)
           : this(new Jwks(keys))
        {
        }

        public JwtReader(params Jwk[] keys)
           : this(new Jwks(keys))
        {
        }

        public JwtReader(IKeyProvider encryptionKeyProvider)
            : this(new[] { encryptionKeyProvider ?? throw new ArgumentNullException(nameof(encryptionKeyProvider)) })
        {
        }

        public JwtReader(Jwks encryptionKeys)
            : this(new StaticKeyProvider(encryptionKeys))
        {
        }

        public JwtReader(Jwk encryptionKey)
            : this(new Jwks(encryptionKey))
        {
        }

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
        /// <param name="token">the JWT encoded as JWE or JWS</param>
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

            if (token.Length > policy.MaximumTokenSizeInBytes)
            {
                return TokenValidationResult.MalformedToken();
            }

            int length = token.Length;
            byte[] utf8ArrayToReturnToPool = null;
            var utf8Buffer = length <= Constants.MaxStackallocBytes
                  ? stackalloc byte[length]
                  : (utf8ArrayToReturnToPool = ArrayPool<byte>.Shared.Rent(length)).AsSpan(0, length);
            try
            {
#if !NETSTANDARD2_0
                Encoding.UTF8.GetBytes(token, utf8Buffer);
#else
                EncodingHelper.GetUtf8Bytes(token, utf8Buffer);
#endif             
                return TryReadToken(utf8Buffer, policy);
            }
            finally
            {
                if (utf8ArrayToReturnToPool != null)
                {
                    ArrayPool<byte>.Shared.Return(utf8ArrayToReturnToPool);
                }
            }
        }

        private TokenValidationResult TryReadToken(ReadOnlySpan<byte> utf8Buffer, TokenValidationPolicy policy)
        {
            Span<TokenSegment> segments = stackalloc TokenSegment[Constants.JweSegmentCount];
            var segmentCount = Tokenizer.Tokenize(utf8Buffer, segments, Constants.JweSegmentCount);
            var headerSegment = segments[0];
            if (headerSegment.IsEmpty)
            {
                return TokenValidationResult.MalformedToken();
            }

            JwtHeader header;
            var rawHeader = utf8Buffer.Slice(headerSegment.Start, headerSegment.Length);
            try
            {
                if (EnableHeaderCaching)
                {
                    if (!_headerCache.TryGetHeader(rawHeader, out header))
                    {
                        header = GetJsonObject<JwtHeader>(rawHeader);
                        _headerCache.AddHeader(rawHeader, header);
                    }
                }
                else
                {
                    header = GetJsonObject<JwtHeader>(rawHeader);
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

            switch (segmentCount)
            {
                case Constants.JwsSegmentCount:
                    return TryReadJws(utf8Buffer, policy, segments, headerSegment, header);
                case Constants.JweSegmentCount:
                    return TryReadJwe(utf8Buffer, policy, segments, header, rawHeader);
                default:
                    return TokenValidationResult.MalformedToken();
            }
        }

        private TokenValidationResult TryReadJwe(
            ReadOnlySpan<byte> utf8Buffer,
            TokenValidationPolicy policy,
            Span<TokenSegment> segments,
            JwtHeader header,
            ReadOnlySpan<byte> rawHeader)
        {
            var enc = (EncryptionAlgorithm)header.Enc;
            if (enc == EncryptionAlgorithm.Empty)
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

            Span<byte> decryptedBytes = new byte[Base64Url.GetArraySizeRequiredToDecode(rawCiphertext.Length)];
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

            var zip = (CompressionAlgorithm)header.Zip;
            if (zip != CompressionAlgorithm.Empty)
            {
                Compressor compressionProvider = zip.Compressor;
                if (compressionProvider == null)
                {
                    return TokenValidationResult.InvalidHeader(HeaderParameters.Zip);
                }

                try
                {
                    decryptedBytes = compressionProvider.Decompress(decryptedBytes);
                }
                catch (Exception e)
                {
                    return TokenValidationResult.DecompressionFailed(e);
                }
            }

            Jwt jwe;
            if (!string.Equals(header.Cty, ContentTypeValues.Jwt, StringComparison.Ordinal))
            {
                // The decrypted payload is not a nested JWT
                jwe = new Jwt(header, decryptedBytes.ToArray(), decryptionKey);
                return TokenValidationResult.Success(jwe);
            }

            var decryptionResult = TryReadToken(decryptedBytes, policy);
            if (!decryptionResult.Succedeed)
            {
                return decryptionResult;
            }

            var decryptedJwt = decryptionResult.Token;
            jwe = new Jwt(header, decryptedJwt, decryptionKey);
            return TokenValidationResult.Success(jwe);
        }

        private TokenValidationResult TryReadJws(
            ReadOnlySpan<byte> utf8Buffer,
            TokenValidationPolicy policy,
            Span<TokenSegment> segments,
            TokenSegment headerSegment,
            JwtHeader header)
        {
            var payloadSegment = segments[1];
            var rawPayload = utf8Buffer.Slice(payloadSegment.Start, payloadSegment.Length);
            JwtPayload payload;
            try
            {
                payload = GetJsonObject<JwtPayload>(rawPayload);
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
            return policy.TryValidate(new TokenValidationContext(utf8Buffer, jws, _signatureFactory, new TokenSegment(headerSegment.Start, headerSegment.Length + payloadSegment.Length + 1), segments[2]));
        }

        private static T GetJsonObject<T>(ReadOnlySpan<byte> data)
        {
            int base64UrlLength = Base64Url.GetArraySizeRequiredToDecode(data.Length);
            byte[] base64UrlArrayToReturnToPool = null;
            var buffer = base64UrlLength <= Constants.MaxStackallocBytes
              ? stackalloc byte[base64UrlLength]
              : (base64UrlArrayToReturnToPool = ArrayPool<byte>.Shared.Rent(base64UrlLength)).AsSpan(0, base64UrlLength);
            try
            {
                Base64Url.Base64UrlDecode(data, buffer);
#if !NETSTANDARD2_0
                var json = Encoding.UTF8.GetString(buffer);
#else
                var json = Encoding.UTF8.GetString(buffer.ToArray());
#endif
                return JsonConvert.DeserializeObject<T>(json);
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
            var decryptionProvider = _authenticatedEncryptionFactory.Create(key, encryptionAlgorithm);
            if (decryptionProvider == null)
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

                if (!decryptionProvider.TryDecrypt(
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
            var operationResult = Base64Url.Base64UrlDecode(rawEncryptedKey, encryptedKey, out int bytesConsumed, out int bytesWritten);
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
            var kid = header.Kid;
            var alg = header.Alg;

            var keys = new List<Jwk>(1);
            for (int i = 0; i < _encryptionKeyProviders.Length; i++)
            {
                var keySet = _encryptionKeyProviders[i].GetKeys(header);

                for (int j = 0; j < keySet.Count; j++)
                {
                    var key = keySet[j];
                    if ((string.IsNullOrEmpty(key.Use) || string.Equals(key.Use, JsonWebKeyUseNames.Enc, StringComparison.Ordinal)) &&
                        (string.IsNullOrEmpty(key.Alg) || string.Equals(key.Alg, alg, StringComparison.Ordinal)))
                    {
                        keys.Add(key);
                    }
                }
            }

            return keys;
        }

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