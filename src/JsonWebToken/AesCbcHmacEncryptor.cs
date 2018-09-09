using JsonWebToken.ObjectPooling;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;

namespace JsonWebToken
{
    /// <summary>
    /// Provides authenticated encryption and decryption services.
    /// </summary>
    public sealed class AesCbcHmacEncryptor : AuthenticatedEncryptor
    {
        private readonly SignatureAlgorithm _signatureAlgorithm;
        private readonly SymmetricSigner _symmetricSignatureProvider;
        private readonly ObjectPool<Aes> _aesPool;

        /// <summary>
        /// Initializes a new instance of the <see cref="AesCbcHmacEncryptor"/> class used for encryption and decryption.
        /// <param name="key">The <see cref="JsonWebKey"/> that will be used for crypto operations.</param>
        /// <param name="encryptionAlgorithm">The encryption algorithm to apply.</param>
        /// </summary>
        public AesCbcHmacEncryptor(SymmetricJwk key, EncryptionAlgorithm encryptionAlgorithm)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (encryptionAlgorithm.Category != EncryptionTypes.AesHmac)
            {
                throw new ArgumentException(ErrorMessages.NotSupportedEncryptionAlgorithm(encryptionAlgorithm));
            }

            ValidateKeySize(key, encryptionAlgorithm);
            int keyLength = encryptionAlgorithm.RequiredKeySizeInBytes / 2;

            var keyBytes = key.RawK.AsSpan();
            var aesKey = keyBytes.Slice(keyLength).ToArray();
            var hmacKey = SymmetricJwk.FromSpan(keyBytes.Slice(0, keyLength), false);

            _aesPool = new ObjectPool<Aes>(new AesPooledPolicy(aesKey));
            _signatureAlgorithm = encryptionAlgorithm.SignatureAlgorithm;
            _symmetricSignatureProvider = hmacKey.CreateSigner(_signatureAlgorithm, true) as SymmetricSigner;
            if (_symmetricSignatureProvider == null)
            {
                throw new NotSupportedException(ErrorMessages.NotSupportedSignatureAlgorithm(_signatureAlgorithm));
            }
        }

        public override int GetCiphertextSize(int plaintextSize)
        {
            return (plaintextSize + 16) & ~15;
        }

        public override int GetTagSize()
        {
            return _symmetricSignatureProvider.HashSizeInBytes;
        }

        public override int GetNonceSize()
        {
            return 16;
        }

        public override void Encrypt(
            ReadOnlySpan<byte> plaintext,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> associatedData,
            Span<byte> ciphertext,
            Span<byte> tag)
        {
            if (plaintext.IsEmpty)
            {
                throw new ArgumentNullException(nameof(plaintext));
            }

            if (associatedData.IsEmpty)
            {
                throw new ArgumentNullException(nameof(associatedData));
            }

            byte[] arrayToReturnToPool = null;
            Aes aes = _aesPool.Get();
            try
            {
                aes.IV = nonce.ToArray();

                Transform(aes.CreateEncryptor(), plaintext, 0, plaintext.Length, ciphertext);

                int macLength = associatedData.Length + nonce.Length + ciphertext.Length + sizeof(long);
                Span<byte> macBytes = macLength <= Constants.MaxStackallocBytes
                    ? stackalloc byte[macLength]
                    : (arrayToReturnToPool = ArrayPool<byte>.Shared.Rent(macLength)).AsSpan(0, macLength);

                associatedData.CopyTo(macBytes);
                nonce.CopyTo(macBytes.Slice(associatedData.Length));
                ciphertext.CopyTo(macBytes.Slice(associatedData.Length + nonce.Length));
                BinaryPrimitives.WriteInt64BigEndian(macBytes.Slice(associatedData.Length + nonce.Length + ciphertext.Length, sizeof(long)), associatedData.Length * 8);

                _symmetricSignatureProvider.TrySign(macBytes, tag, out int writtenBytes);
                Debug.Assert(writtenBytes == tag.Length);
            }
            catch
            {
                ciphertext.Clear();
                throw;
            }
            finally
            {
                _aesPool.Return(aes);
                if (arrayToReturnToPool != null)
                {
                    ArrayPool<byte>.Shared.Return(arrayToReturnToPool);
                }
            }
        }

        /// <summary>
        /// Decrypts ciphertext into plaintext
        /// </summary>
        /// <param name="ciphertext">the encrypted text to decrypt.</param>
        /// <param name="associatedData">the authenticateData that is used in verification.</param>
        /// <param name="nonce">the initialization vector used when creating the ciphertext.</param>
        /// <param name="authenticationTag">the authenticationTag that was created during the encyption.</param>
        /// <returns>decrypted ciphertext</returns>
        public override bool TryDecrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> authenticationTag, Span<byte> plaintext, out int bytesWritten)
        {
            if (ciphertext.IsEmpty)
            {
                throw new ArgumentNullException(nameof(ciphertext));
            }

            if (associatedData.IsEmpty)
            {
                throw new ArgumentNullException(nameof(associatedData));
            }

            if (nonce.IsEmpty)
            {
                throw new ArgumentNullException(nameof(nonce));
            }

            if (authenticationTag.IsEmpty)
            {
                throw new ArgumentNullException(nameof(authenticationTag));
            }

            byte[] byteArrayToReturnToPool = null;
            int macLength = associatedData.Length + nonce.Length + ciphertext.Length + sizeof(long);
            Span<byte> macBytes = macLength <= Constants.MaxStackallocBytes
                                    ? stackalloc byte[macLength]
                                    : (byteArrayToReturnToPool = ArrayPool<byte>.Shared.Rent(macLength)).AsSpan(0, macLength);
            try
            {
                associatedData.CopyTo(macBytes);
                nonce.CopyTo(macBytes.Slice(associatedData.Length));
                ciphertext.CopyTo(macBytes.Slice(associatedData.Length + nonce.Length));
                BinaryPrimitives.WriteInt64BigEndian(macBytes.Slice(associatedData.Length + nonce.Length + ciphertext.Length), associatedData.Length * 8);
                if (!_symmetricSignatureProvider.Verify(macBytes, authenticationTag, _symmetricSignatureProvider.Key.KeySizeInBits >> 3))
                {
                    bytesWritten = 0;
                    plaintext.Clear();
                    return false;
                }

                Aes aes = _aesPool.Get();
                try
                {
                    aes.IV = nonce.ToArray();
                    using (var decryptor = aes.CreateDecryptor())
                    {
                        bytesWritten = Transform(decryptor, ciphertext, 0, ciphertext.Length, plaintext);
                    }

                    return bytesWritten <= ciphertext.Length;
                }
                finally
                {
                    _aesPool.Return(aes);
                }
            }
            catch
            {
                bytesWritten = 0;
                plaintext.Clear();
                return false;
            }
            finally
            {
                if (byteArrayToReturnToPool != null)
                {
                    ArrayPool<byte>.Shared.Return(byteArrayToReturnToPool);
                }
            }
        }

        private void ValidateKeySize(JsonWebKey key, EncryptionAlgorithm encryptionAlgorithm)
        {
            if (key.KeySizeInBits < encryptionAlgorithm.RequiredKeySizeInBytes << 3)
            {
                throw new ArgumentOutOfRangeException(nameof(key.KeySizeInBits), ErrorMessages.EncryptionKeyTooSmall(key, encryptionAlgorithm, encryptionAlgorithm.RequiredKeySizeInBytes << 3, key.KeySizeInBits));
            }
        }

        private static unsafe int Transform(ICryptoTransform transform, ReadOnlySpan<byte> input, int inputOffset, int inputLength, Span<byte> output)
        {
            fixed (byte* buffer = &output[0])
            {
                using (var messageStream = new UnmanagedMemoryStream(buffer, output.Length, output.Length, FileAccess.Write))
                using (CryptoStream cryptoStream = new CryptoStream(messageStream, transform, CryptoStreamMode.Write))
                {
#if NETCOREAPP2_1
                    cryptoStream.Write(input.Slice(inputOffset, inputLength));
#else
                    cryptoStream.Write(input.ToArray(), inputOffset, inputLength);
#endif
                    cryptoStream.FlushFinalBlock();
                    return (int)messageStream.Position;
                }
            }
        }

        public override void Dispose()
        {
            _symmetricSignatureProvider.Dispose();
            _aesPool.Dispose();
        }

        private class AesPooledPolicy : PooledObjectPolicy<Aes>
        {
            private readonly byte[] _key;

            public AesPooledPolicy(byte[] key)
            {
                _key = key;
            }

            public override Aes Create()
            {
                var aes = Aes.Create();
                aes.Key = _key;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                return aes;
            }

            public override bool Return(Aes obj)
            {
                return true;
            }
        }
    }
}
