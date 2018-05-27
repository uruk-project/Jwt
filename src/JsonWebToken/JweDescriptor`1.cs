using System;
using System.Buffers;
using System.Diagnostics;
using System.Text;

namespace JsonWebToken
{
    public abstract class JweDescriptor<TPayload> : JwtDescriptor<TPayload>
    {
        public string EncryptionAlgorithm
        {
            get => GetHeaderParameter(JwtHeaderParameterNames.Enc);
            set => Header[JwtHeaderParameterNames.Enc] = value;
        }

        public string CompressionAlgorithm
        {
            get => GetHeaderParameter(JwtHeaderParameterNames.Zip);
            set => Header[JwtHeaderParameterNames.Zip] = value;
        }

        protected string EncryptToken(string payload)
        {
            var key = Key;
            string encryptionAlgorithm = EncryptionAlgorithm;
            string contentEncryptionAlgorithm = Algorithm;
            if (SecurityAlgorithms.Direct.Equals(contentEncryptionAlgorithm, StringComparison.Ordinal))
            {
                var encryptionProvider = key.CreateAuthenticatedEncryptionProvider(encryptionAlgorithm);
                if (encryptionProvider == null)
                {
                    throw new JsonWebTokenEncryptionFailedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedEncryptionAlgorithm, encryptionAlgorithm));
                }

                var header = new JwtHeader(key, encryptionAlgorithm);
                try
                {
#if NETCOREAPP2_1
                    Span<byte> encodedPayload = stackalloc byte[payload.Length];
                    Encoding.UTF8.GetBytes(payload, encodedPayload);

                    var headerJson = header.ToString();
                    Span<byte> utf8EncodedHeader = stackalloc byte[headerJson.Length];
                    Encoding.UTF8.GetBytes(headerJson, utf8EncodedHeader);

                    Span<char> base64EncodedHeader = stackalloc char[Base64Url.GetArraySizeRequiredToEncode(utf8EncodedHeader.Length)];
                    int bytesWritten = Base64Url.Base64UrlEncode(utf8EncodedHeader, base64EncodedHeader);

                    Span<byte> asciiEncodedHeader = stackalloc byte[bytesWritten];
                    Encoding.ASCII.GetBytes(base64EncodedHeader.Slice(0, bytesWritten), asciiEncodedHeader);

                    var encryptionResult = encryptionProvider.Encrypt(encodedPayload, asciiEncodedHeader);
                    int encryptionLength =
                        base64EncodedHeader.Length
                        + Base64Url.GetArraySizeRequiredToEncode(encryptionResult.IV.Length)
                        + Base64Url.GetArraySizeRequiredToEncode(encryptionResult.Ciphertext.Length)
                        + Base64Url.GetArraySizeRequiredToEncode(encryptionResult.AuthenticationTag.Length)
                        + JwtConstants.JweSeparatorsCount;

                    char[] arrayToReturnToPool = null;
                    try
                    {
                        Span<char> encryptedToken = encryptionLength > JwtConstants.MaxStackallocBytes
                        ? (arrayToReturnToPool = ArrayPool<char>.Shared.Rent(encryptionLength))
                        : stackalloc char[encryptionLength];

                        base64EncodedHeader.CopyTo(encryptedToken);
                        encryptedToken[bytesWritten++] = '.';
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
                        if (arrayToReturnToPool != null)
                        {
                            ArrayPool<char>.Shared.Return(arrayToReturnToPool);
                        }
                    }
#else
                    var encryptionResult = encryptionProvider.Encrypt(Encoding.UTF8.GetBytes(payload), Encoding.ASCII.GetBytes(header.Base64UrlEncode()));
                    return string.Join(
                        ".",
                        header.Base64UrlEncode(),
                        string.Empty,
                        Base64Url.Encode(encryptionResult.IV),
                        Base64Url.Encode(encryptionResult.Ciphertext),
                        Base64Url.Encode(encryptionResult.AuthenticationTag));
#endif
                }
                catch (Exception ex)
                {
                    throw new JsonWebTokenEncryptionFailedException(ErrorMessages.FormatInvariant(ErrorMessages.EncryptionFailed, encryptionAlgorithm, key), ex);
                }
            }
            else
            {
                SymmetricJwk symmetricKey = null;

                // only 128, 384 and 512 AesCbcHmac for CEK algorithm
                if (SecurityAlgorithms.Aes128CbcHmacSha256.Equals(encryptionAlgorithm, StringComparison.Ordinal))
                {
                    symmetricKey = SymmetricJwk.GenerateKey(256);
                }
                else if (SecurityAlgorithms.Aes192CbcHmacSha384.Equals(encryptionAlgorithm, StringComparison.Ordinal))
                {
                    symmetricKey = SymmetricJwk.GenerateKey(384);
                }
                else if (SecurityAlgorithms.Aes256CbcHmacSha512.Equals(encryptionAlgorithm, StringComparison.Ordinal))
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

                byte[] wrappedKey;
                try
                {
                    wrappedKey = kwProvider.WrapKey(symmetricKey.RawK);
                }
                finally
                {
                    key.ReleaseKeyWrapProvider(kwProvider);
                }

                var encryptionProvider = symmetricKey.CreateAuthenticatedEncryptionProvider(encryptionAlgorithm);
                if (encryptionProvider == null)
                {
                    throw new JsonWebTokenEncryptionFailedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedEncryptionAlgorithm, encryptionAlgorithm));
                }

                try
                {
                    var header = new JwtHeader(key, encryptionAlgorithm);

#if NETCOREAPP2_1
                    Span<byte> encodedPayload = stackalloc byte[payload.Length];
                    Encoding.UTF8.GetBytes(payload, encodedPayload);

                    var headerJson = header.ToString();
                    Span<byte> utf8EncodedHeader = stackalloc byte[headerJson.Length];
                    Encoding.UTF8.GetBytes(headerJson, utf8EncodedHeader);

                    Span<char> base64EncodedHeader = stackalloc char[Base64Url.GetArraySizeRequiredToEncode(utf8EncodedHeader.Length)];
                    int bytesWritten = Base64Url.Base64UrlEncode(utf8EncodedHeader, base64EncodedHeader);

                    Span<byte> asciiEncodedHeader = stackalloc byte[bytesWritten];
                    Encoding.ASCII.GetBytes(base64EncodedHeader.Slice(0, bytesWritten), asciiEncodedHeader);

                    var encryptionResult = encryptionProvider.Encrypt(encodedPayload, asciiEncodedHeader);
                    int encryptionLength =
                        base64EncodedHeader.Length
                        + Base64Url.GetArraySizeRequiredToEncode(wrappedKey.Length)
                        + Base64Url.GetArraySizeRequiredToEncode(encryptionResult.IV.Length)
                        + Base64Url.GetArraySizeRequiredToEncode(encryptionResult.Ciphertext.Length)
                        + Base64Url.GetArraySizeRequiredToEncode(encryptionResult.AuthenticationTag.Length)
                        + JwtConstants.JweSeparatorsCount;

                    char[] arrayToReturnToPool = null;
                    try
                    {
                        Span<char> encryptedToken = encryptionLength > JwtConstants.MaxStackallocBytes
                        ? (arrayToReturnToPool = ArrayPool<char>.Shared.Rent(encryptionLength))
                        : stackalloc char[encryptionLength];

                        base64EncodedHeader.CopyTo(encryptedToken);
                        encryptedToken[bytesWritten++] = '.';
                        bytesWritten += Base64Url.Base64UrlEncode(wrappedKey, encryptedToken.Slice(bytesWritten));
                        encryptedToken[bytesWritten++] = '.';
                        bytesWritten += Base64Url.Base64UrlEncode(encryptionResult.IV, encryptedToken.Slice(bytesWritten));
                        encryptedToken[bytesWritten++] = '.';
                        bytesWritten += Base64Url.Base64UrlEncode(encryptionResult.Ciphertext, encryptedToken.Slice(bytesWritten));
                        encryptedToken[bytesWritten++] = '.';
                        bytesWritten += Base64Url.Base64UrlEncode(encryptionResult.AuthenticationTag, encryptedToken.Slice(bytesWritten));
                        Debug.Assert(bytesWritten == encryptedToken.Length);

                        return encryptedToken.ToString();
                    }
                    finally
                    {
                        if (arrayToReturnToPool != null)
                        {
                            ArrayPool<char>.Shared.Return(arrayToReturnToPool);
                        }
                    }
#else
                    var encryptionResult = encryptionProvider.Encrypt(Encoding.UTF8.GetBytes(payload), Encoding.ASCII.GetBytes(header.Base64UrlEncode()));
                    return string.Join(
                        ".",
                        header.Base64UrlEncode(),
                        Base64Url.Encode(wrappedKey),
                        Base64Url.Encode(encryptionResult.IV),
                        Base64Url.Encode(encryptionResult.Ciphertext),
                        Base64Url.Encode(encryptionResult.AuthenticationTag));
#endif
                }
                catch (Exception ex)
                {
                    throw new JsonWebTokenEncryptionFailedException(ErrorMessages.FormatInvariant(ErrorMessages.EncryptionFailed, encryptionAlgorithm, key), ex);
                }
            }
        }
    }
}
