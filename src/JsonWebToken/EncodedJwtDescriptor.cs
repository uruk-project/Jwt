using System;
using System.Buffers;
using System.Diagnostics;
using System.Text;

namespace JsonWebToken
{
    public abstract class EncodedJwtDescriptor<TPayload> : JwtDescriptor<TPayload>
    {
        public string EncryptionAlgorithm
        {
            get => GetHeaderParameter(HeaderParameterNames.Enc);
            set => Header[HeaderParameterNames.Enc] = value;
        }

        public string CompressionAlgorithm
        {
            get => GetHeaderParameter(HeaderParameterNames.Zip);
            set => Header[HeaderParameterNames.Zip] = value;
        }

        protected string EncryptToken(string payload)
        {
            if (payload == null)
            {
                throw new ArgumentNullException(nameof(payload));
            }

            string encryptionAlgorithm = EncryptionAlgorithm;
            string contentEncryptionAlgorithm = Algorithm;

            JsonWebKey key = Key;
            AuthenticatedEncryptionProvider encryptionProvider;
            byte[] wrappedKey = null;
            if (string.Equals(KeyManagementAlgorithms.Direct, contentEncryptionAlgorithm, StringComparison.Ordinal))
            {
                encryptionProvider = key.CreateAuthenticatedEncryptionProvider(encryptionAlgorithm);
            }
            else
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

                var kwProvider = key.CreateKeyWrapProvider(contentEncryptionAlgorithm);
                if (kwProvider == null)
                {
                    throw new JsonWebTokenEncryptionFailedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSuportedAlgorithmForKeyWrap, encryptionAlgorithm));
                }

                try
                {
                    wrappedKey = kwProvider.WrapKey(symmetricKey.RawK);
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

            var header = new JwtHeader(key, encryptionAlgorithm);
            try
            {
#if NETCOREAPP2_1
                var headerJson = header.ToString();
                int payloadLength = payload.Length;
                int headerJsonLength = headerJson.Length;
                int base64EncodedHeaderLength = Base64Url.GetArraySizeRequiredToEncode(headerJsonLength);
                int bufferLength = payloadLength + base64EncodedHeaderLength;
                byte[] arrayByteToReturnToPool = null;
                char[] arrayCharToReturnToPool = null;
                char[] buffer64HeaderToReturnToPool = null;
                Span<byte> buffer = bufferLength > JwtConstants.MaxStackallocBytes
                                    ? (arrayByteToReturnToPool = ArrayPool<byte>.Shared.Rent(bufferLength)).AsSpan(0, bufferLength)
                                    : stackalloc byte[bufferLength];

                try
                {
                    Span<byte> utf8EncodedHeader = buffer.Slice(0, headerJsonLength);
                    Encoding.UTF8.GetBytes(headerJson, utf8EncodedHeader);

                    Span<char> base64EncodedHeader = base64EncodedHeaderLength > JwtConstants.MaxStackallocBytes
                                                    ? (buffer64HeaderToReturnToPool = ArrayPool<char>.Shared.Rent(base64EncodedHeaderLength)).AsSpan(0, base64EncodedHeaderLength)
                                                    : stackalloc char[base64EncodedHeaderLength];
                    int bytesWritten = Base64Url.Base64UrlEncode(utf8EncodedHeader, base64EncodedHeader);

                    Span<byte> asciiEncodedHeader = buffer.Slice(0, base64EncodedHeaderLength);
                    Encoding.ASCII.GetBytes(base64EncodedHeader, asciiEncodedHeader);

                    Span<byte> encodedPayload = buffer.Slice(base64EncodedHeaderLength, payloadLength);
                    Encoding.UTF8.GetBytes(payload, encodedPayload);

                    var encryptionResult = encryptionProvider.Encrypt(encodedPayload, asciiEncodedHeader);
                    int encryptionLength =
                        base64EncodedHeader.Length
                        + Base64Url.GetArraySizeRequiredToEncode(encryptionResult.IV.Length)
                        + Base64Url.GetArraySizeRequiredToEncode(encryptionResult.Ciphertext.Length)
                        + Base64Url.GetArraySizeRequiredToEncode(encryptionResult.AuthenticationTag.Length)
                        + JwtConstants.JweSeparatorsCount;
                    if (wrappedKey != null)
                    {
                        encryptionLength += Base64Url.GetArraySizeRequiredToEncode(wrappedKey.Length);
                    }

                    Span<char> encryptedToken = encryptionLength > JwtConstants.MaxStackallocBytes
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
                    Debug.Assert(encryptedToken.Length == bytesWritten);

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
                }
#else
                var encryptionResult = encryptionProvider.Encrypt(Encoding.UTF8.GetBytes(payload), Encoding.ASCII.GetBytes(header.Base64UrlEncode()));
                if (wrappedKey == null)
                {
                    return string.Join(
                        ".",
                        header.Base64UrlEncode(),
                        string.Empty,
                        Base64Url.Encode(encryptionResult.IV),
                        Base64Url.Encode(encryptionResult.Ciphertext),
                        Base64Url.Encode(encryptionResult.AuthenticationTag));
                }
                else
                {
                    return string.Join(
                        ".",
                        header.Base64UrlEncode(),
                        Base64Url.Encode(wrappedKey),
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