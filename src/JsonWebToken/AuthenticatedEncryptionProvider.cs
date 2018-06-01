using System;
using System.Buffers;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;

namespace JsonWebToken
{
    /// <summary>
    /// Provides authenticated encryption and decryption services.
    /// </summary>
    public class AuthenticatedEncryptionProvider : IDisposable
    {
        private struct AuthenticatedKeys
        {
            public SymmetricJwk AesKey;
            public SymmetricJwk HmacKey;
        }

        private readonly AuthenticatedKeys _authenticatedkeys;
        private readonly string _hashAlgorithm;
        private readonly SymmetricSignatureProvider _symmetricSignatureProvider;

        /// <summary>
        /// Initializes a new instance of the <see cref="AuthenticatedEncryptionProvider"/> class used for encryption and decryption.
        /// <param name="key">The <see cref="SecurityKey"/> that will be used for crypto operations.</param>
        /// <param name="algorithm">The encryption algorithm to apply.</param>
        /// </summary>
        public AuthenticatedEncryptionProvider(SymmetricJwk key, string algorithm)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (string.IsNullOrWhiteSpace(algorithm))
            {
                throw new ArgumentNullException(nameof(algorithm));
            }

            if (!IsSupportedAlgorithm(key, algorithm))
            {
                throw new ArgumentException(ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedEncryptionAlgorithm, algorithm));
            }

            ValidateKeySize(key, algorithm);
            _authenticatedkeys = GetAlgorithmParameters(key, algorithm);
            _hashAlgorithm = GetHashAlgorithm(algorithm);
            _symmetricSignatureProvider = _authenticatedkeys.HmacKey.CreateSignatureProvider(_hashAlgorithm, true) as SymmetricSignatureProvider;
            if (_symmetricSignatureProvider == null)
            {
                throw new ArgumentException(ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedSignatureHashAlgorithm, Algorithm));
            }

            Key = key;
            Algorithm = algorithm;
        }

        /// <summary>
        /// Gets the encryption algorithm that is being used.
        /// </summary>
        public string Algorithm { get; private set; }

        /// <summary>
        /// Gets the <see cref="JsonWebKey"/> that is being used.
        /// </summary>
        public JsonWebKey Key { get; private set; }

        /// <summary>
        /// Encrypts the 'plaintext'
        /// </summary>
        /// <param name="plaintext">the data to be encrypted.</param>
        /// <param name="authenticatedData">will be combined with iv and ciphertext to create an authenticationtag.</param>
        /// <returns><see cref="AuthenticatedEncryptionResult"/>containing ciphertext, iv, authenticationtag.</returns>
        /// <exception cref="ArgumentNullException">plaintext is null or empty.</exception>
        /// <exception cref="ArgumentNullException">authenticationData is null or empty.</exception>
        /// <exception cref="JsonWebTokenEncryptionFailedException">AES crypto operation threw. See inner exception for details.</exception>
        public AuthenticatedEncryptionResult Encrypt(byte[] plaintext, byte[] authenticatedData)
        {
            return Encrypt(plaintext, authenticatedData, null);
        }

#if NETCOREAPP2_1
        public AuthenticatedEncryptionResult Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> authenticatedData)
        {
            return Encrypt(plaintext, authenticatedData, null);
        }

        /// <summary>
        /// Encrypts the 'plaintext'
        /// </summary>
        /// <param name="plaintext">the data to be encrypted.</param>
        /// <param name="authenticatedData">will be combined with iv and ciphertext to create an authenticationtag.</param>
        /// <param name="iv">initialization vector for encryption.</param>
        public AuthenticatedEncryptionResult Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> authenticatedData, byte[] iv)
        {
            if (plaintext == null || plaintext.Length == 0)
            {
                throw new ArgumentNullException(nameof(plaintext));
            }

            if (authenticatedData == null || authenticatedData.Length == 0)
            {
                throw new ArgumentNullException(nameof(authenticatedData));
            }

            using (Aes aes = Aes.Create())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = _authenticatedkeys.AesKey.RawK;
                if (iv != null)
                {
                    aes.IV = iv;
                }

                byte[] ciphertext;
                ciphertext = Transform(aes.CreateEncryptor(), plaintext, 0, plaintext.Length);
                
                byte[] arrayToReturnToPool = null;
                int macLength = authenticatedData.Length + aes.IV.Length + ciphertext.Length + sizeof(long);
                Span<byte> macBytes = macLength <= JwtConstants.MaxStackallocBytes
                    ? stackalloc byte[macLength]
                    : (arrayToReturnToPool = ArrayPool<byte>.Shared.Rent(macLength)).AsSpan(0, macLength);
                try
                {
                    authenticatedData.CopyTo(macBytes);
                    aes.IV.CopyTo(macBytes.Slice(authenticatedData.Length));
                    ciphertext.CopyTo(macBytes.Slice(authenticatedData.Length + aes.IV.Length));
                    TryConvertToBigEndian(macBytes.Slice(authenticatedData.Length + aes.IV.Length + ciphertext.Length, sizeof(long)), authenticatedData.Length * 8);

                    byte[] authenticationTag = new byte[_symmetricSignatureProvider.HashSizeInBits / 8];
                    _symmetricSignatureProvider.TrySign(macBytes, authenticationTag, out int writtenBytes);
                    Debug.Assert(writtenBytes == authenticationTag.Length);

                    return new AuthenticatedEncryptionResult(ciphertext, aes.IV, authenticationTag);
                }
                finally
                {
                    if (arrayToReturnToPool != null)
                    {
                        ArrayPool<byte>.Shared.Return(arrayToReturnToPool);
                    }
                }
            }
        }
#endif

        /// <summary>
        /// Encrypts the 'plaintext'
        /// </summary>
        /// <param name="plaintext">the data to be encrypted.</param>
        /// <param name="authenticatedData">will be combined with iv and ciphertext to create an authenticationtag.</param>
        /// <param name="iv">initialization vector for encryption.</param>
        public AuthenticatedEncryptionResult Encrypt(byte[] plaintext, byte[] authenticatedData, byte[] iv)
        {
            if (plaintext == null || plaintext.Length == 0)
            {
                throw new ArgumentNullException(nameof(plaintext));
            }

            if (authenticatedData == null || authenticatedData.Length == 0)
            {
                throw new ArgumentNullException(nameof(authenticatedData));
            }

            Aes aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = _authenticatedkeys.AesKey.RawK;
            if (iv != null)
            {
                aes.IV = iv;
            }

            byte[] ciphertext;
            ciphertext = Transform(aes.CreateEncryptor(), plaintext, 0, plaintext.Length);

            byte[] al = ConvertToBigEndian(authenticatedData.Length * 8);
            byte[] macBytes = new byte[authenticatedData.Length + aes.IV.Length + ciphertext.Length + al.Length];
            Array.Copy(authenticatedData, 0, macBytes, 0, authenticatedData.Length);
            Array.Copy(aes.IV, 0, macBytes, authenticatedData.Length, aes.IV.Length);
            Array.Copy(ciphertext, 0, macBytes, authenticatedData.Length + aes.IV.Length, ciphertext.Length);
            Array.Copy(al, 0, macBytes, authenticatedData.Length + aes.IV.Length + ciphertext.Length, al.Length);
            byte[] macHash = new byte[_symmetricSignatureProvider.HashSizeInBits / 8];
            _symmetricSignatureProvider.TrySign(macBytes, macHash, out int writtenBytes);

            var authenticationTag = new byte[writtenBytes];
            Array.Copy(macHash, authenticationTag, authenticationTag.Length);

            return new AuthenticatedEncryptionResult(ciphertext, aes.IV, authenticationTag);
        }

        /// <summary>
        /// Decrypts ciphertext into plaintext
        /// </summary>
        /// <param name="ciphertext">the encrypted text to decrypt.</param>
        /// <param name="authenticatedData">the authenticateData that is used in verification.</param>
        /// <param name="iv">the initialization vector used when creating the ciphertext.</param>
        /// <param name="authenticationTag">the authenticationTag that was created during the encyption.</param>
        /// <returns>decrypted ciphertext</returns>
        public byte[] Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> authenticatedData, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> authenticationTag)
        {
            if (ciphertext == null || ciphertext.Length == 0)
            {
                throw new ArgumentNullException(nameof(ciphertext));
            }

            if (authenticatedData == null || authenticatedData.Length == 0)
            {
                throw new ArgumentNullException(nameof(authenticatedData));
            }

            if (iv == null || iv.Length == 0)
            {
                throw new ArgumentNullException(nameof(iv));
            }

            if (authenticationTag == null || authenticationTag.Length == 0)
            {
                throw new ArgumentNullException(nameof(authenticationTag));
            }

            byte[] byteArrayToReturnToPool = null;
            int macLength = authenticatedData.Length + iv.Length + ciphertext.Length + sizeof(long);
            Span<byte> macBytes = macLength <= JwtConstants.MaxStackallocBytes
                                    ? stackalloc byte[macLength]
                                    : (byteArrayToReturnToPool = ArrayPool<byte>.Shared.Rent(macLength)).AsSpan(0, macLength);
            try
            {
                authenticatedData.CopyTo(macBytes);
                iv.CopyTo(macBytes.Slice(authenticatedData.Length));
                ciphertext.CopyTo(macBytes.Slice(authenticatedData.Length + iv.Length));
#if NETCOREAPP2_1
                TryConvertToBigEndian(macBytes.Slice(authenticatedData.Length + iv.Length + ciphertext.Length), authenticatedData.Length * 8);
#else
            var al = ConvertToBigEndian(authenticatedData.Length * 8);
            al.CopyTo(macBytes.Slice(authenticatedData.Length + iv.Length + ciphertext.Length));
#endif
                if (!_symmetricSignatureProvider.Verify(macBytes, authenticationTag, _authenticatedkeys.HmacKey.KeySize / 8))
                {
                    return null;
                }
            }
            finally
            {
                if (byteArrayToReturnToPool != null)
                {
                    ArrayPool<byte>.Shared.Return(byteArrayToReturnToPool);
                }
            }

            Aes aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = _authenticatedkeys.AesKey.RawK;
            aes.IV = iv.ToArray();
            try
            {
                return Transform(aes.CreateDecryptor(), ciphertext.ToArray(), 0, ciphertext.Length);
            }
            catch
            {
                return null;
            }
        }

        private bool IsSupportedAlgorithm(SymmetricJwk key, string algorithm)
        {
            if (key == null)
            {
                return false;
            }

            if (string.IsNullOrEmpty(algorithm))
            {
                return false;
            }

            if (!(string.Equals(algorithm, ContentEncryptionAlgorithms.Aes128CbcHmacSha256, StringComparison.Ordinal)
               || string.Equals(algorithm, ContentEncryptionAlgorithms.Aes192CbcHmacSha384, StringComparison.Ordinal)
               || string.Equals(algorithm, ContentEncryptionAlgorithms.Aes256CbcHmacSha512, StringComparison.Ordinal)))
            {
                return false;
            }

            return true;
        }

        private AuthenticatedKeys GetAlgorithmParameters(SymmetricJwk key, string algorithm)
        {
            int keyLength;
            if (string.Equals(algorithm, ContentEncryptionAlgorithms.Aes256CbcHmacSha512, StringComparison.Ordinal))
            {
                keyLength = 32;
            }
            else if (string.Equals(algorithm, ContentEncryptionAlgorithms.Aes192CbcHmacSha384, StringComparison.Ordinal))
            {
                keyLength = 24;
            }
            else if (string.Equals(algorithm, ContentEncryptionAlgorithms.Aes128CbcHmacSha256, StringComparison.Ordinal))
            {
                keyLength = 16;
            }
            else
            {
                throw new ArgumentException(ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedEncryptionAlgorithm, algorithm));
            }

            var keyBytes = key.RawK;
            byte[] aesKey = new byte[keyLength];
            byte[] hmacKey = new byte[keyLength];
            Array.Copy(keyBytes, keyLength, aesKey, 0, keyLength);
            Array.Copy(keyBytes, hmacKey, keyLength);
            return new AuthenticatedKeys()
            {
                AesKey = SymmetricJwk.FromByteArray(aesKey),
                HmacKey = SymmetricJwk.FromByteArray(hmacKey)
            };
        }

        private string GetHashAlgorithm(string algorithm)
        {
            if (string.Equals(ContentEncryptionAlgorithms.Aes128CbcHmacSha256, algorithm, StringComparison.Ordinal))
            {
                return SignatureAlgorithms.HmacSha256;
            }

            if (string.Equals(ContentEncryptionAlgorithms.Aes192CbcHmacSha384, algorithm, StringComparison.Ordinal))
            {
                return SignatureAlgorithms.HmacSha384;
            }

            if (string.Equals(ContentEncryptionAlgorithms.Aes256CbcHmacSha512, algorithm, StringComparison.Ordinal))
            {
                return SignatureAlgorithms.HmacSha512;
            }

            throw new ArgumentException(ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedAlgorithm, algorithm), nameof(algorithm));
        }

        private void ValidateKeySize(JsonWebKey key, string algorithm)
        {
            if (string.Equals(ContentEncryptionAlgorithms.Aes128CbcHmacSha256, algorithm, StringComparison.Ordinal))
            {
                if (key.KeySize < 256)
                {
                    throw new ArgumentOutOfRangeException(nameof(key.KeySize), ErrorMessages.FormatInvariant(ErrorMessages.EncryptionKeyTooSmall, key.Kid, algorithm, 256, key.KeySize));
                }

                return;
            }

            if (string.Equals(ContentEncryptionAlgorithms.Aes192CbcHmacSha384, algorithm, StringComparison.Ordinal))
            {
                if (key.KeySize < 384)
                {
                    throw new ArgumentOutOfRangeException(nameof(key.KeySize), ErrorMessages.FormatInvariant(ErrorMessages.EncryptionKeyTooSmall, key.Kid, algorithm, 384, key.KeySize));
                }

                return;
            }

            if (string.Equals(ContentEncryptionAlgorithms.Aes256CbcHmacSha512, algorithm, StringComparison.Ordinal))
            {
                if (key.KeySize < 512)
                {
                    throw new ArgumentOutOfRangeException(nameof(key.KeySize), ErrorMessages.FormatInvariant(ErrorMessages.EncryptionKeyTooSmall, key.Kid, algorithm, 512, key.KeySize));
                }

                return;
            }

            throw new ArgumentException(ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedAlgorithm, algorithm));
        }

        private static byte[] ConvertToBigEndian(long i)
        {
            byte[] temp = BitConverter.GetBytes(i);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(temp);
            }

            return temp;
        }

#if NETCOREAPP2_1
        private static bool TryConvertToBigEndian(Span<byte> destination, long i)
        {
            if (BitConverter.TryWriteBytes(destination, i))
            {
                if (BitConverter.IsLittleEndian)
                {
                    destination.Slice(0, sizeof(long)).Reverse();
                }

                return true;
            }

            return false;
        }
#endif

        private static byte[] Transform(ICryptoTransform transform, ReadOnlySpan<byte> input, int inputOffset, int inputLength)
        {
            if (transform.CanTransformMultipleBlocks)
            {
                return transform.TransformFinalBlock(input.ToArray(), inputOffset, inputLength);
            }

            using (MemoryStream messageStream = new MemoryStream())
            using (CryptoStream cryptoStream = new CryptoStream(messageStream, transform, CryptoStreamMode.Write))
            {
#if NETCOREAPP2_1
                cryptoStream.Write(input.Slice(inputOffset, inputLength));
#else
                cryptoStream.Write(input.ToArray(), inputOffset, inputLength);
#endif
                cryptoStream.FlushFinalBlock();

                return messageStream.ToArray();
            }
        }

        public void Dispose()
        {
            if (_symmetricSignatureProvider != null)
            {
                _symmetricSignatureProvider.Dispose();
            }
        }
    }
}
