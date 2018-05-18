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
#if NETCOREAPP2_1
            string rawData = null;
            if (useSpan)
            {
                unsafe
                {
                    //Span<byte> buffer = new byte[2 * 1024 * 10];
                    var array = ArrayPool<byte>.Shared.Rent(2 * 1024);
                    Span<byte> buffer = array;
                    header.TryBase64UrlEncode(buffer, out int headerBytesWritten);
                    buffer[headerBytesWritten] = dot;
                    payload.TryBase64UrlEncode(buffer.Slice(headerBytesWritten + 1), out int payloadBytesWritten);
                    buffer[payloadBytesWritten + headerBytesWritten + 1] = dot;
                    int sigBytesWritten = 0;
                    if (descriptor.SigningKey != null)
                    {
                        TryCreateEncodedSignature(buffer, buffer.Slice(payloadBytesWritten + headerBytesWritten + 2), descriptor.SigningKey, out sigBytesWritten);
                    }

                    rawData = Encoding.UTF8.GetString(buffer.Slice(0, payloadBytesWritten + headerBytesWritten + 2 + sigBytesWritten));
                    ArrayPool<byte>.Shared.Return(array);
                }
            }
            else
            {
                string rawHeader = header.Base64UrlEncode();
                string rawPayload = payload.Base64UrlEncode();
                string rawSignature = descriptor.SigningKey == null ? string.Empty : CreateEncodedSignature(string.Concat(rawHeader, ".", rawPayload), descriptor.SigningKey, useSpan);

                rawData = string.Concat(rawHeader, ".", rawPayload, ".", rawSignature);
            }
#else
            string rawHeader = header.Base64UrlEncode();
            string rawPayload = payload.Base64UrlEncode();
            string rawSignature = descriptor.SigningKey == null ? string.Empty : CreateEncodedSignature(string.Concat(rawHeader, ".", rawPayload), descriptor.SigningKey, useSpan);

            var rawData = string.Concat(rawHeader, ".", rawPayload, ".", rawSignature);
#endif
            if (descriptor.EncryptingKey != null)
            {
                rawData = EncryptToken(rawData, descriptor.EncryptingKey, descriptor.EncryptionAlgorithm);
            }

            return rawData;
        }

        private string EncryptToken(string payload, JsonWebKey key, string encryptionAlgorithm)
        {
            // if direct algorithm, look for support
            if (SecurityAlgorithms.Direct.Equals(key.Alg, StringComparison.Ordinal))
            {
                var encryptionProvider = key.CreateAuthenticatedEncryptionProvider(encryptionAlgorithm);
                if (encryptionProvider == null)
                {
                    throw new JsonWebTokenEncryptionFailedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedEncryptionAlgorithm, encryptionAlgorithm));
                }

                var header = new JwtHeader(key, encryptionAlgorithm);
                try
                {
                    var encryptionResult = encryptionProvider.Encrypt(Encoding.UTF8.GetBytes(payload), Encoding.ASCII.GetBytes(header.Base64UrlEncode()));
                    return string.Join(
                        ".",
                        header.Base64UrlEncode(),
                        string.Empty,
                        Base64UrlEncoder.Encode(encryptionResult.IV),
                        Base64UrlEncoder.Encode(encryptionResult.Ciphertext),
                        Base64UrlEncoder.Encode(encryptionResult.AuthenticationTag));
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

                var kwProvider = key.CreateKeyWrapProvider(key.Alg);
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
                    var header = new JwtHeader(key);
                    var encryptionResult = encryptionProvider.Encrypt(Encoding.UTF8.GetBytes(payload), Encoding.ASCII.GetBytes(header.Base64UrlEncode()));
                    return string.Join(
                        ".",
                        header.Base64UrlEncode(),
                        Base64UrlEncoder.Encode(wrappedKey),
                        Base64UrlEncoder.Encode(encryptionResult.IV),
                        Base64UrlEncoder.Encode(encryptionResult.Ciphertext),
                        Base64UrlEncoder.Encode(encryptionResult.AuthenticationTag));
                }
                catch (Exception ex)
                {
                    throw new JsonWebTokenEncryptionFailedException(ErrorMessages.FormatInvariant(ErrorMessages.EncryptionFailed, encryptionAlgorithm, key), ex);
                }
            }
        }

        private static byte[] GenerateKeyBytes(int sizeInBits)
        {
            byte[] key = null;
            if (sizeInBits != 256 && sizeInBits != 384 && sizeInBits != 512)
            {
                throw new ArgumentException(ErrorMessages.InvalidSymmetricKeySize, nameof(sizeInBits));
            }

            using (var aes = Aes.Create())
            {
                int halfSizeInBytes = sizeInBits >> 4;
                key = new byte[halfSizeInBytes << 1];
                aes.KeySize = sizeInBits >> 1;
                // The design of AuthenticatedEncryption needs two keys of the same size - generate them, each half size of what's required
                aes.GenerateKey();
                Array.Copy(aes.Key, key, halfSizeInBytes);
                aes.GenerateKey();
                Array.Copy(aes.Key, 0, key, halfSizeInBytes, halfSizeInBytes);
            }

            return key;
        }

#if NETCOREAPP2_1
        private OperationStatus TryCreateEncodedSignature(ReadOnlySpan<byte> input, Span<byte> destination, JsonWebKey key, out int bytesWritten)
        {
            if (input == null)
            {
                throw new ArgumentNullException(nameof(input));
            }

            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            var signatureProvider = key.CreateSignatureProvider(key.Alg, true);
            if (signatureProvider == null)
            {
                throw new NotSupportedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedSignatureAlgorithm, (key == null ? "Null" : key.ToString()), (key.Alg ?? "Null")));
            }

            var signature = ArrayPool<byte>.Shared.Rent(key.SignatureSize);
            Span<byte> temp = signature;
            try
            {
                if (signatureProvider.TrySign(input, signature, out int signLength))
                {
                    return Base64UrlEncoder.Base64UrlEncode(temp.Slice(0, signLength), destination, out int bytesConsumed, out bytesWritten);
                }
                else
                {
                    throw new Exception("Key : " + key.Alg + " / " + key.KeySize + " / " + signLength);
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(signature);
                key.ReleaseSignatureProvider(signatureProvider);
            }
        }
#endif
        private string CreateEncodedSignature(string input, JsonWebKey key, bool useSpan)
        {
            if (input == null)
            {
                throw new ArgumentNullException(nameof(input));
            }

            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            var signatureProvider = key.CreateSignatureProvider(key.Alg, true);
            if (signatureProvider == null)
            {
                throw new NotSupportedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedSignatureAlgorithm, (key == null ? "Null" : key.ToString()), (key.Alg ?? "Null")));
            }

            try
            {
                return Base64UrlEncoder.Encode(signatureProvider.Sign(Encoding.UTF8.GetBytes(input)));
            }
            finally
            {
                key.ReleaseSignatureProvider(signatureProvider);
            }
        }
    }
}
