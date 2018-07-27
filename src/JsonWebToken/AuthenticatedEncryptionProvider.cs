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

            if (algorithm == null)
            {
                throw new ArgumentNullException(nameof(algorithm));
            }

            if (!IsSupportedAlgorithm(algorithm))
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

            Algorithm = algorithm;
        }

        /// <summary>
        /// Gets the encryption algorithm that is being used.
        /// </summary>
        public string Algorithm { get; private set; }

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
            return Encrypt(plaintext.AsSpan(), authenticatedData.AsSpan());
        }

        /// <summary>
        /// Encrypts the 'plaintext'
        /// </summary>
        /// <param name="plaintext">the data to be encrypted.</param>
        /// <param name="authenticatedData">will be combined with iv and ciphertext to create an authenticationtag.</param>
        public AuthenticatedEncryptionResult Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> authenticatedData)
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

                byte[] ciphertext;
                ciphertext = Transform(aes.CreateEncryptor(), plaintext.ToArray(), 0, plaintext.Length);

                byte[] arrayToReturnToPool = null;
                int macLength = authenticatedData.Length + aes.IV.Length + ciphertext.Length + sizeof(long);
                Span<byte> macBytes = macLength <= Constants.MaxStackallocBytes
                    ? stackalloc byte[macLength]
                    : (arrayToReturnToPool = ArrayPool<byte>.Shared.Rent(macLength)).AsSpan(0, macLength);
                try
                {
                    authenticatedData.CopyTo(macBytes);
                    aes.IV.CopyTo(macBytes.Slice(authenticatedData.Length));
                    ciphertext.CopyTo(macBytes.Slice(authenticatedData.Length + aes.IV.Length));
#if NETCOREAPP2_1
                    TryConvertToBigEndian(macBytes.Slice(authenticatedData.Length + aes.IV.Length + ciphertext.Length, sizeof(long)), authenticatedData.Length * 8);
#else
                    var al = ConvertToBigEndian(authenticatedData.Length * 8);
                    al.CopyTo(macBytes.Slice(authenticatedData.Length + aes.IV.Length + ciphertext.Length, sizeof(long)));
#endif
                    byte[] authenticationTag = new byte[_symmetricSignatureProvider.HashSizeInBytes];
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
            if (ciphertext == null || ciphertext.IsEmpty)
            {
                throw new ArgumentNullException(nameof(ciphertext));
            }

            if (authenticatedData == null || authenticatedData.IsEmpty)
            {
                throw new ArgumentNullException(nameof(authenticatedData));
            }

            if (iv == null || iv.IsEmpty)
            {
                throw new ArgumentNullException(nameof(iv));
            }

            if (authenticationTag == null || authenticationTag.IsEmpty)
            {
                throw new ArgumentNullException(nameof(authenticationTag));
            }

            byte[] byteArrayToReturnToPool = null;
            int macLength = authenticatedData.Length + iv.Length + ciphertext.Length + sizeof(long);
            Span<byte> macBytes = macLength <= Constants.MaxStackallocBytes
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
                if (!_symmetricSignatureProvider.Verify(macBytes, authenticationTag, _authenticatedkeys.HmacKey.KeySizeInBits / 8))
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

        private static bool IsSupportedAlgorithm(string algorithm)
        {
            switch (algorithm)
            {
                case ContentEncryptionAlgorithms.Aes128CbcHmacSha256:
                case ContentEncryptionAlgorithms.Aes192CbcHmacSha384:
                case ContentEncryptionAlgorithms.Aes256CbcHmacSha512:
                    return true;
                default:
                    return false;
            }
        }

        private AuthenticatedKeys GetAlgorithmParameters(SymmetricJwk key, string algorithm)
        {
            int keyLength;
            switch (algorithm)
            {
                case ContentEncryptionAlgorithms.Aes128CbcHmacSha256:
                    keyLength = 16;
                    break;
                case ContentEncryptionAlgorithms.Aes192CbcHmacSha384:
                    keyLength = 24;
                    break;
                case ContentEncryptionAlgorithms.Aes256CbcHmacSha512:
                    keyLength = 32;
                    break;
                default:
                    throw new ArgumentException(ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedEncryptionAlgorithm, algorithm));
            }

            var keyBytes = key.RawK;
            byte[] aesKey = new byte[keyLength];
            byte[] hmacKey = new byte[keyLength];
            Array.Copy(keyBytes, keyLength, aesKey, 0, keyLength);
            Array.Copy(keyBytes, hmacKey, keyLength);
            return new AuthenticatedKeys()
            {
                AesKey = SymmetricJwk.FromByteArray(aesKey, false),
                HmacKey = SymmetricJwk.FromByteArray(hmacKey, false)
            };
        }

        private string GetHashAlgorithm(string algorithm)
        {
            switch (algorithm)
            {
                case ContentEncryptionAlgorithms.Aes128CbcHmacSha256:
                    return SignatureAlgorithms.HmacSha256;
                case ContentEncryptionAlgorithms.Aes192CbcHmacSha384:
                    return SignatureAlgorithms.HmacSha384;
                case ContentEncryptionAlgorithms.Aes256CbcHmacSha512:
                    return SignatureAlgorithms.HmacSha512;
                default:
                    throw new ArgumentException(ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedAlgorithm, algorithm), nameof(algorithm));
            }
        }

        private void ValidateKeySize(JsonWebKey key, string algorithm)
        {
            switch (algorithm)
            {
                case ContentEncryptionAlgorithms.Aes128CbcHmacSha256:
                    if (key.KeySizeInBits < 256)
                    {
                        throw new ArgumentOutOfRangeException(nameof(key.KeySizeInBits), ErrorMessages.FormatInvariant(ErrorMessages.EncryptionKeyTooSmall, key.Kid, algorithm, 256, key.KeySizeInBits));
                    }
                    break;
                case ContentEncryptionAlgorithms.Aes192CbcHmacSha384:
                    if (key.KeySizeInBits < 384)
                    {
                        throw new ArgumentOutOfRangeException(nameof(key.KeySizeInBits), ErrorMessages.FormatInvariant(ErrorMessages.EncryptionKeyTooSmall, key.Kid, algorithm, 384, key.KeySizeInBits));
                    }
                    break;
                case ContentEncryptionAlgorithms.Aes256CbcHmacSha512:
                    if (key.KeySizeInBits < 512)
                    {
                        throw new ArgumentOutOfRangeException(nameof(key.KeySizeInBits), ErrorMessages.FormatInvariant(ErrorMessages.EncryptionKeyTooSmall, key.Kid, algorithm, 512, key.KeySizeInBits));
                    }
                    break;
                default:
                    throw new ArgumentException(ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedAlgorithm, algorithm));
            }
        }

#if NETCOREAPP2_1
        private static bool TryConvertToBigEndian(Span<byte> destination, long i)
        {
            ulong value = (ulong)i;
            if (BitConverter.IsLittleEndian)
            {
                value = (value << 32) | (value >> 32);
                value = (value & 0x0000FFFF0000FFFF) << 16 | (value & 0xFFFF0000FFFF0000) >> 16;
                value = (value & 0x00FF00FF00FF00FF) << 8 | (value & 0xFF00FF00FF00FF00) >> 8;
            }

            return BitConverter.TryWriteBytes(destination, value);
        }

#else
        private static byte[] ConvertToBigEndian(long i)
        {
            ulong value = (ulong)i;
            if (BitConverter.IsLittleEndian)
            {
                value = (value << 32) | (value >> 32);
                value = (value & 0x0000FFFF0000FFFF) << 16 | (value & 0xFFFF0000FFFF0000) >> 16;
                value = (value & 0x00FF00FF00FF00FF) << 8 | (value & 0xFF00FF00FF00FF00) >> 8;
            }

            byte[] temp = BitConverter.GetBytes(value);

            return temp;
        }
#endif

#if NETCOREAPP2_1
        private static byte[] Transform(ICryptoTransform transform, ReadOnlySpan<byte> input, int inputOffset, int inputLength)
        {
            if (transform.CanTransformMultipleBlocks)
            {
                return transform.TransformFinalBlock(input.ToArray(), inputOffset, inputLength);
            }

            using (MemoryStream messageStream = new MemoryStream())
            using (CryptoStream cryptoStream = new CryptoStream(messageStream, transform, CryptoStreamMode.Write))
            {
                cryptoStream.Write(input.Slice(inputOffset, inputLength));
                cryptoStream.FlushFinalBlock();

                return messageStream.ToArray();
            }
        }

#else
        private static byte[] Transform(ICryptoTransform transform, byte[] input, int inputOffset, int inputLength)
        {
            if (transform.CanTransformMultipleBlocks)
            {
                return transform.TransformFinalBlock(input, inputOffset, inputLength);
            }

            using (MemoryStream messageStream = new MemoryStream())
            using (CryptoStream cryptoStream = new CryptoStream(messageStream, transform, CryptoStreamMode.Write))
            {
                cryptoStream.Write(input, inputOffset, inputLength);
                cryptoStream.FlushFinalBlock();

                return messageStream.ToArray();
            }
        }
#endif

        public void Dispose()
        {
            if (_symmetricSignatureProvider != null)
            {
                _symmetricSignatureProvider.Dispose();
            }
        }
    }
}
