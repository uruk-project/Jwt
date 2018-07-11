using Newtonsoft.Json.Linq;
using System;
using System.Buffers;
using System.Text;

namespace JsonWebToken
{
    public abstract class EncryptedJwtDescriptor<TPayload> : JwtDescriptor<TPayload> where TPayload : class
    {
        public EncryptedJwtDescriptor(JObject header, TPayload payload)
            : base(header, payload)
        {
        }

        public EncryptedJwtDescriptor(TPayload payload)
            : base(payload)
        {
        }

        public string EncryptionAlgorithm
        {
            get => GetHeaderParameter(HeaderParameters.Enc);
            set => Header[HeaderParameters.Enc] = value;
        }

        public string CompressionAlgorithm
        {
            get => GetHeaderParameter(HeaderParameters.Zip);
            set => Header[HeaderParameters.Zip] = value;
        }

#if NETCOREAPP2_1
        unsafe protected string EncryptToken(string payload)
        {
            if (payload == null)
            {
                throw new ArgumentNullException(nameof(payload));
            }

            int payloadLength = payload.Length;
            byte[] payloadToReturnToPool = null;
            Span<byte> encodedPayload = payloadLength > Constants.MaxStackallocBytes
                             ? (payloadToReturnToPool = ArrayPool<byte>.Shared.Rent(payloadLength)).AsSpan(0, payloadLength)
                             : stackalloc byte[payloadLength];

            try
            {
                Encoding.UTF8.GetBytes(payload, encodedPayload);
            return EncryptToken(encodedPayload);
            }
            finally
            {
                if (payloadToReturnToPool != null)
                {
                    ArrayPool<byte>.Shared.Return(payloadToReturnToPool);
                }
            }
        }
#else
        unsafe protected string EncryptToken(string payload)
        {
            if (payload == null)
            {
                throw new ArgumentNullException(nameof(payload));
            }

            var encodedPayload = Encoding.UTF8.GetBytes(payload);
            return EncryptToken(encodedPayload);
        }
#endif
        unsafe protected string EncryptToken(Span<byte> payload)
        {
            string encryptionAlgorithm = EncryptionAlgorithm;
            string contentEncryptionAlgorithm = Algorithm;
            bool IsDirectEncryption = string.Equals(KeyManagementAlgorithms.Direct, contentEncryptionAlgorithm, StringComparison.Ordinal);
            JsonWebKey key = Key;
            AuthenticatedEncryptionProvider encryptionProvider = null;
            KeyWrapProvider kwProvider = null;
            if (IsDirectEncryption)
            {
                encryptionProvider = key.CreateAuthenticatedEncryptionProvider(encryptionAlgorithm);
            }
            else
            {
                kwProvider = key.CreateKeyWrapProvider(contentEncryptionAlgorithm);
                if (kwProvider == null)
                {
                    throw new JsonWebTokenEncryptionFailedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSuportedAlgorithmForKeyWrap, encryptionAlgorithm));
                }
            }

            Span<byte> wrappedKey = IsDirectEncryption ? null : stackalloc byte[kwProvider.GetKeyWrapSize(encryptionAlgorithm)];
            if (!IsDirectEncryption)
            {
                SymmetricJwk symmetricKey;
                if (string.Equals(ContentEncryptionAlgorithms.Aes128CbcHmacSha256, encryptionAlgorithm, StringComparison.Ordinal))
                {
                    symmetricKey = SymmetricJwk.GenerateKey(256);
                }
                else if (string.Equals(ContentEncryptionAlgorithms.Aes192CbcHmacSha384, encryptionAlgorithm, StringComparison.Ordinal))
                {
                    symmetricKey = SymmetricJwk.GenerateKey(384);
                }
                else if (string.Equals(ContentEncryptionAlgorithms.Aes256CbcHmacSha512, encryptionAlgorithm, StringComparison.Ordinal))
                {
                    symmetricKey = SymmetricJwk.GenerateKey(512);
                }
                else
                {
                    throw new JsonWebTokenEncryptionFailedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSuportedAlgorithmForKeyWrap, encryptionAlgorithm));
                }

                try
                {
                    kwProvider.WrapKey(symmetricKey.RawK, wrappedKey, out var keyWrappedBytesWritten);
                }
                finally
                {
                    key.ReleaseKeyWrapProvider(kwProvider);
                }

                encryptionProvider = symmetricKey.CreateAuthenticatedEncryptionProvider(encryptionAlgorithm);
            }

            if (encryptionProvider == null)
            {
                throw new JsonWebTokenEncryptionFailedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedEncryptionAlgorithm, encryptionAlgorithm));
            }

            Header[HeaderParameters.Enc] = encryptionAlgorithm;
            Header[HeaderParameters.Alg] = key.Alg;
            Header[HeaderParameters.Kid] = key.Kid;

            try
            {
#if NETCOREAPP2_1
                var headerJson = Serialize(Header);
                int headerJsonLength = headerJson.Length;
                int base64EncodedHeaderLength = Base64Url.GetArraySizeRequiredToEncode(headerJsonLength);

                byte[] arrayByteToReturnToPool = null;
                char[] arrayCharToReturnToPool = null;
                char[] buffer64HeaderToReturnToPool = null;
                Span<byte> asciiEncodedHeader = base64EncodedHeaderLength > Constants.MaxStackallocBytes
                                    ? (arrayByteToReturnToPool = ArrayPool<byte>.Shared.Rent(base64EncodedHeaderLength)).AsSpan(0, base64EncodedHeaderLength)
                                    : stackalloc byte[base64EncodedHeaderLength];
                byte[] payloadToReturn = null;

                try
                {
                    Span<byte> utf8EncodedHeader = asciiEncodedHeader.Slice(0, headerJsonLength);
                    Encoding.UTF8.GetBytes(headerJson, utf8EncodedHeader);

                    Span<char> base64EncodedHeader = base64EncodedHeaderLength > Constants.MaxStackallocBytes
                                                    ? (buffer64HeaderToReturnToPool = ArrayPool<char>.Shared.Rent(base64EncodedHeaderLength)).AsSpan(0, base64EncodedHeaderLength)
                                                    : stackalloc char[base64EncodedHeaderLength];
                    int bytesWritten = Base64Url.Base64UrlEncode(utf8EncodedHeader, base64EncodedHeader);

                    Encoding.ASCII.GetBytes(base64EncodedHeader, asciiEncodedHeader);

                    CompressionProvider compressionProvider = null;
                    if (CompressionAlgorithm != null)
                    {
                        compressionProvider = CompressionProvider.CreateCompressionProvider(CompressionAlgorithm);
                        if (compressionProvider == null)
                        {
                            throw new JsonWebTokenEncryptionFailedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSuportedCompressionAlgorithm, CompressionAlgorithm));
                        }
                    }

                    if (compressionProvider != null)
                    {
                        payload = compressionProvider.Compress(payload);
                    }

                    var encryptionResult = encryptionProvider.Encrypt(payload, asciiEncodedHeader);

                    int encryptionLength =
                        base64EncodedHeader.Length
                        + Base64Url.GetArraySizeRequiredToEncode(encryptionResult.IV.Length)
                        + Base64Url.GetArraySizeRequiredToEncode(encryptionResult.Ciphertext.Length)
                        + Base64Url.GetArraySizeRequiredToEncode(encryptionResult.AuthenticationTag.Length)
                        + Constants.JweSegmentCount - 1;
                    if (wrappedKey != null)
                    {
                        encryptionLength += Base64Url.GetArraySizeRequiredToEncode(wrappedKey.Length);
                    }

                    Span<char> encryptedToken = encryptionLength > Constants.MaxStackallocBytes
                                                ? (arrayCharToReturnToPool = ArrayPool<char>.Shared.Rent(encryptionLength)).AsSpan(0, encryptionLength)
                                                : stackalloc char[encryptionLength];

                    base64EncodedHeader.CopyTo(encryptedToken);
                    encryptedToken[bytesWritten++] = '.';
                    if (wrappedKey != null)
                    {
                        bytesWritten += Base64Url.Base64UrlEncode(wrappedKey, encryptedToken.Slice(bytesWritten));
                    }

                    encryptedToken[bytesWritten++] = '.';
                    bytesWritten += Base64Url.Base64UrlEncode(encryptionResult.IV, encryptedToken.Slice(bytesWritten));
                    encryptedToken[bytesWritten++] = '.';
                    bytesWritten += Base64Url.Base64UrlEncode(encryptionResult.Ciphertext, encryptedToken.Slice(bytesWritten));
                    encryptedToken[bytesWritten++] = '.';
                    bytesWritten += Base64Url.Base64UrlEncode(encryptionResult.AuthenticationTag, encryptedToken.Slice(bytesWritten));
                    //Debug.Assert(encryptedToken.Length == bytesWritten);

                    return encryptedToken.ToString();
                }
                finally
                {
                    if (arrayCharToReturnToPool != null)
                    {
                        ArrayPool<char>.Shared.Return(arrayCharToReturnToPool);
                    }

                    if (arrayByteToReturnToPool != null)
                    {
                        ArrayPool<byte>.Shared.Return(arrayByteToReturnToPool);
                    }

                    if (buffer64HeaderToReturnToPool != null)
                    {
                        ArrayPool<char>.Shared.Return(buffer64HeaderToReturnToPool);
                    }

                    if (payloadToReturn != null)
                    {
                        ArrayPool<byte>.Shared.Return(payloadToReturn);
                    }
                }
#else
                var utf8Header = Encoding.UTF8.GetBytes(Serialize(Header));
                var base64Header = Base64Url.Encode(utf8Header);
                CompressionProvider compressionProvider = null;
                if (CompressionAlgorithm != null)
                {
                    compressionProvider = CompressionProvider.CreateCompressionProvider(CompressionAlgorithm);
                    if (compressionProvider == null)
                    {
                        throw new JsonWebTokenEncryptionFailedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSuportedCompressionAlgorithm, CompressionAlgorithm));
                    }
                }

                if (compressionProvider != null)
                {
                    payload = compressionProvider.Compress(payload);
                }
                var encryptionResult = encryptionProvider.Encrypt(payload.ToArray(), Encoding.ASCII.GetBytes(base64Header));

                if (wrappedKey == null)
                {
                    return string.Join(
                        ".",
                        base64Header,
                        string.Empty,
                        Base64Url.Encode(encryptionResult.IV),
                        Base64Url.Encode(encryptionResult.Ciphertext),
                        Base64Url.Encode(encryptionResult.AuthenticationTag));
                }
                else
                {
                    return string.Join(
                        ".",
                        base64Header,
                        Base64Url.Encode(wrappedKey.ToArray()),
                        Base64Url.Encode(encryptionResult.IV),
                        Base64Url.Encode(encryptionResult.Ciphertext),
                        Base64Url.Encode(encryptionResult.AuthenticationTag));
                }
#endif
            }
            catch (Exception ex)
            {
                throw new JsonWebTokenEncryptionFailedException(ErrorMessages.FormatInvariant(ErrorMessages.EncryptionFailed, encryptionAlgorithm, key.Kid), ex);
            }
        }
    }
}