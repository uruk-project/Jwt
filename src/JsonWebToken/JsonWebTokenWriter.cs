using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Buffers;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace JsonWebToken
{
    /// <summary>
    /// See: http://tools.ietf.org/html/rfc7519 and http://www.rfc-editor.org/info/rfc7515
    /// </summary>
    public class JsonWebTokenWriter
    {
        private int _defaultTokenLifetimeInMinutes = DefaultTokenLifetimeInMinutes;

        private static readonly byte dot = Convert.ToByte('.');

        /// <summary>
        /// Default lifetime of tokens created. When creating tokens, if 'expires' and 'notbefore' are both null, then a default will be set to: expires = DateTime.UtcNow, notbefore = DateTime.UtcNow + TimeSpan.FromMinutes(TokenLifetimeInMinutes).
        /// </summary>
        public static readonly int DefaultTokenLifetimeInMinutes = 60;

        /// <summary>
        /// Gets or sets the token lifetime in minutes.
        /// </summary>
        /// <remarks>Used by <see cref="CreateToken(JsonWebTokenDescriptor)"/> to set the default expiration ('exp'). <see cref="DefaultTokenLifetimeInMinutes"/> for the default.</remarks>
        /// <exception cref="ArgumentOutOfRangeException">'value' less than 1.</exception>
        public int TokenLifetimeInMinutes
        {
            get
            {
                return _defaultTokenLifetimeInMinutes;
            }

            set
            {
                if (value < 1)
                {
                    throw new ArgumentOutOfRangeException(nameof(value), ErrorMessages.FormatInvariant(ErrorMessages.MustBeGreaterThanZero, nameof(TokenLifetimeInMinutes), value));
                }

                _defaultTokenLifetimeInMinutes = value;
            }
        }

        /// <summary>
        /// Gets or sets a bool that controls if token creation will validate 'exp', 'nbf' and 'iat' if specified.
        /// </summary>
        /// <remarks>See: <see cref="DefaultTokenLifetimeInMinutes"/>, <see cref="TokenLifetimeInMinutes"/> for defaults and configuration.</remarks>
        public bool ValidateLifetimeOnTokenCreation { get; set; } = false;

        /// <summary>
        /// Gets or sets a bool that controls if token creation will set default 'exp', 'nbf' and 'iat' if not specified.
        /// </summary>
        /// <remarks>See: <see cref="DefaultTokenLifetimeInMinutes"/>, <see cref="TokenLifetimeInMinutes"/> for defaults and configuration.</remarks>
        public bool SetDefaultTimesOnTokenCreation { get; set; } = false;

        public string WriteToken(JsonWebTokenDescriptor descriptor, bool useSpan = false)
        {
            if (descriptor == null)
            {
                throw new ArgumentNullException(nameof(descriptor));
            }

            if (SetDefaultTimesOnTokenCreation && (!descriptor.Expires.HasValue || !descriptor.IssuedAt.HasValue || !descriptor.NotBefore.HasValue))
            {
                DateTime now = DateTime.UtcNow;
                if (!descriptor.Expires.HasValue)
                {
                    descriptor.Expires = now + TimeSpan.FromMinutes(TokenLifetimeInMinutes);
                }

                if (!descriptor.IssuedAt.HasValue)
                {
                    descriptor.IssuedAt = now;
                }
            }

            JwtPayload payload = new JwtPayload(descriptor.Payload);
            JwtHeader header = descriptor.SigningKey == null ? new JwtHeader() : new JwtHeader(descriptor.SigningKey);
            foreach (var item in descriptor.Header)
            {
                header[item.Key] = item.Value;
            }

            unsafe
            {
                var headerJson = header.SerializeToJson();
                var payloadJson = payload.SerializeToJson();
                SignatureProvider signatureProvider = null;
                if (descriptor.SigningKey != null)
                {
                    var key = descriptor.SigningKey;
                    signatureProvider = key.CreateSignatureProvider(key.Alg, true);
                    if (signatureProvider == null)
                    {
                        throw new NotSupportedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedSignatureAlgorithm, (key == null ? "Null" : key.Kid), (key.Alg ?? "Null")));
                    }
                }

                int length = Base64Url.GetArraySizeRequiredToEncode(headerJson.Length)
                    + Base64Url.GetArraySizeRequiredToEncode(payloadJson.Length)
                    + Base64Url.GetArraySizeRequiredToEncode(signatureProvider?.HashSize ?? 0)
                    + 2;
                Span<byte> buffer = stackalloc byte[length];

                header.TryBase64UrlEncode(buffer, out int headerBytesWritten);
                buffer[headerBytesWritten] = dot;
                payload.TryBase64UrlEncode(buffer.Slice(headerBytesWritten + 1), out int payloadBytesWritten);
                buffer[payloadBytesWritten + headerBytesWritten + 1] = dot;
                int signatureBytesWritten = 0;
                if (signatureProvider != null)
                {
                    Span<byte> signature = stackalloc byte[signatureProvider.HashSize];
                    try
                    {
                        signatureProvider.TrySign(buffer.Slice(0, payloadBytesWritten + headerBytesWritten + 1), signature, out int signLength);
                        Base64Url.Base64UrlEncode(signature, buffer.Slice(payloadBytesWritten + headerBytesWritten + 2), out int bytesConsumed, out signatureBytesWritten);
                    }
                    finally
                    {
                        descriptor.SigningKey.ReleaseSignatureProvider(signatureProvider);
                    }
                }

#if NETCOREAPP2_1
                string rawData = Encoding.UTF8.GetString(buffer.Slice(0, payloadBytesWritten + headerBytesWritten + 2 + signatureBytesWritten));
#else
                string rawData = Encoding.UTF8.GetString(buffer.Slice(0, payloadBytesWritten + headerBytesWritten + 2 + signatureBytesWritten).ToArray());
#endif
                if (descriptor.EncryptingKey != null)
                {
                    rawData = EncryptToken(rawData, descriptor.EncryptingKey, descriptor.EncryptionAlgorithm, descriptor.ContentEncryptionAlgorithm, useSpan);
                }

                return rawData;
            }
        }

        private string EncryptToken(string payload, JsonWebKey key, string encryptionAlgorithm, string contentEncryptionAlgorithm, bool useSpan)
        {
            // if direct algorithm, look for support
            if (SecurityAlgorithms.Direct.Equals(contentEncryptionAlgorithm, StringComparison.Ordinal))
            {
                var encryptionProvider = key.CreateAuthenticatedEncryptionProvider(encryptionAlgorithm);
                if (encryptionProvider == null)
                {
                    throw new JsonWebTokenEncryptionFailedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedEncryptionAlgorithm, encryptionAlgorithm));
                }

                var header = new JwtHeader(key, encryptionAlgorithm, contentEncryptionAlgorithm);
                try
                {
#if NETCOREAPP2_1
                    Span<byte> encodedPayload = stackalloc byte[payload.Length];
                    Encoding.UTF8.GetBytes(payload, encodedPayload);

                    var headerJson = header.SerializeToJson();
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
                        + 4;

                    Span<char> encryptedToken = stackalloc char[encryptionLength];

                    base64EncodedHeader.CopyTo(encryptedToken);
                    encryptedToken[bytesWritten++] = '.';
                    encryptedToken[bytesWritten++] = '.';
                    bytesWritten += Base64Url.Base64UrlEncode(encryptionResult.IV, encryptedToken.Slice(bytesWritten));
                    encryptedToken[bytesWritten++] = '.';
                    bytesWritten += Base64Url.Base64UrlEncode(encryptionResult.Ciphertext, encryptedToken.Slice(bytesWritten));
                    encryptedToken[bytesWritten++] = '.';
                    bytesWritten += Base64Url.Base64UrlEncode(encryptionResult.AuthenticationTag, encryptedToken.Slice(bytesWritten));

                    return encryptedToken.Slice(0, bytesWritten).ToString();
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
                    symmetricKey = SymmetricJwk.FromByteArray(GenerateKeyBytes(256));
                }
                else if (SecurityAlgorithms.Aes192CbcHmacSha384.Equals(encryptionAlgorithm, StringComparison.Ordinal))
                {
                    symmetricKey = SymmetricJwk.FromByteArray(GenerateKeyBytes(384));
                }
                else if (SecurityAlgorithms.Aes256CbcHmacSha512.Equals(encryptionAlgorithm, StringComparison.Ordinal))
                {
                    symmetricKey = SymmetricJwk.FromByteArray(GenerateKeyBytes(512));
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
                    var header = new JwtHeader(key, encryptionAlgorithm, contentEncryptionAlgorithm);

#if NETCOREAPP2_1
                    Span<byte> encodedPayload = stackalloc byte[payload.Length];
                    Encoding.UTF8.GetBytes(payload, encodedPayload);

                    var headerJson = header.SerializeToJson();
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
                        + 4;

                    Span<char> encryptedToken = stackalloc char[encryptionLength];

                    base64EncodedHeader.CopyTo(encryptedToken);
                    encryptedToken[bytesWritten++] = '.';
                    bytesWritten += Base64Url.Base64UrlEncode(wrappedKey, encryptedToken.Slice(bytesWritten));
                    encryptedToken[bytesWritten++] = '.';
                    bytesWritten += Base64Url.Base64UrlEncode(encryptionResult.IV, encryptedToken.Slice(bytesWritten));
                    encryptedToken[bytesWritten++] = '.';
                    bytesWritten += Base64Url.Base64UrlEncode(encryptionResult.Ciphertext, encryptedToken.Slice(bytesWritten));
                    encryptedToken[bytesWritten++] = '.';
                    bytesWritten += Base64Url.Base64UrlEncode(encryptionResult.AuthenticationTag, encryptedToken.Slice(bytesWritten));

                    return encryptedToken.Slice(0, bytesWritten).ToString();

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

        private static byte[] GenerateKeyBytes(int sizeInBits)
        {
            if (sizeInBits != 256 && sizeInBits != 384 && sizeInBits != 512)
            {
                throw new ArgumentException(ErrorMessages.InvalidSymmetricKeySize, nameof(sizeInBits));
            }

            using (var aes = Aes.Create())
            {
                int halfSizeInBytes = sizeInBits >> 4;
                byte[] key = new byte[halfSizeInBytes << 1];
                aes.KeySize = sizeInBits >> 1;

                aes.GenerateKey();
                Array.Copy(aes.Key, key, halfSizeInBytes);
                aes.GenerateKey();
                Array.Copy(aes.Key, 0, key, halfSizeInBytes, halfSizeInBytes);

                return key;
            }
        }

        //private OperationStatus TryCreateEncodedSignature(ReadOnlySpan<byte> input, Span<byte> destination, JsonWebKey key, out int bytesWritten)
        //{

        //}

        public bool TryBase64UrlEncode(JObject jObject, Span<byte> destination, out int bytesWritten)
        {
            var json = jObject.ToString(Formatting.None);
#if NETCOREAPP2_1
            unsafe
            {
                Span<byte> encodedBytes = stackalloc byte[json.Length];
                Encoding.UTF8.GetBytes(json, encodedBytes);
                var status = Base64Url.Base64UrlEncode(encodedBytes, destination, out int bytesConsumed, out bytesWritten);
                return status == OperationStatus.Done;
            }
#else
            var encodedBytes = Encoding.UTF8.GetBytes(json);

            var status = Base64Url.Base64UrlEncode(encodedBytes, destination, out int bytesConsumed, out bytesWritten);
            return status == OperationStatus.Done;
#endif
        }
    }
}
