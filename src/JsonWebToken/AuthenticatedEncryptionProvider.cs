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
        private readonly SignatureAlgorithm _signatureAlgorithm;
        private readonly SymmetricSignatureProvider _symmetricSignatureProvider;

        /// <summary>
        /// Initializes a new instance of the <see cref="AuthenticatedEncryptionProvider"/> class used for encryption and decryption.
        /// <param name="key">The <see cref="JsonWebKey"/> that will be used for crypto operations.</param>
        /// <param name="encryptionAlgorithm">The encryption algorithm to apply.</param>
        /// </summary>
        public AuthenticatedEncryptionProvider(SymmetricJwk key, EncryptionAlgorithm encryptionAlgorithm)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }
            
            if (encryptionAlgorithm.Category != EncryptionTypes.AesHmac)
            {
                throw new ArgumentException(ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedEncryptionAlgorithm, encryptionAlgorithm));
            }

            ValidateKeySize(key, encryptionAlgorithm);
            _authenticatedkeys = GetAlgorithmParameters(key, encryptionAlgorithm);
            _signatureAlgorithm = encryptionAlgorithm.SignatureAlgorithm;
            _symmetricSignatureProvider = _authenticatedkeys.HmacKey.CreateSignatureProvider(_signatureAlgorithm, true) as SymmetricSignatureProvider;
            if (_symmetricSignatureProvider == null)
            {
                throw new ArgumentException(ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedSignatureHashAlgorithm, encryptionAlgorithm));
            }
        }

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

        private static AuthenticatedKeys GetAlgorithmParameters(SymmetricJwk key, in EncryptionAlgorithm encryptionAlgorithm)
        {
            int keyLength = encryptionAlgorithm.RequiredKeySizeInBytes / 2;

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
        
        private void ValidateKeySize(JsonWebKey key, in EncryptionAlgorithm encryptionAlgorithm)
        {
            if (key.KeySizeInBits < encryptionAlgorithm.RequiredKeySizeInBytes << 3)
            {
                throw new ArgumentOutOfRangeException(nameof(key.KeySizeInBits), ErrorMessages.FormatInvariant(ErrorMessages.EncryptionKeyTooSmall, key.Kid, encryptionAlgorithm, encryptionAlgorithm.RequiredKeySizeInBytes << 3, key.KeySizeInBits));
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
