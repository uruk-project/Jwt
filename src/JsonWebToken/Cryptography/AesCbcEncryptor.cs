// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.Security.Cryptography;

namespace JsonWebToken.Internal
{
    internal sealed class AesCbcEncryptor : AesEncryptor
    {
        private readonly ObjectPool<Aes> _aesPool;
        private bool _disposed;

        public AesCbcEncryptor(ReadOnlySpan<byte> key, EncryptionAlgorithm encryptionAlgorithm)
        {
            if (encryptionAlgorithm is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.encryptionAlgorithm);
            }

            if (encryptionAlgorithm.Category != EncryptionType.AesHmac)
            {
                ThrowHelper.ThrowNotSupportedException_EncryptionAlgorithm(encryptionAlgorithm);
            }

            int keyLength = encryptionAlgorithm.RequiredKeySizeInBits >> 4;
            if (key.Length < keyLength)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException_EncryptionKeyTooSmall(encryptionAlgorithm, encryptionAlgorithm.RequiredKeySizeInBits, encryptionAlgorithm.RequiredKeySizeInBits >> 4);
            }

            var aesKey = key.ToArray();

            _aesPool = new ObjectPool<Aes>(new AesPooledPolicy(aesKey));
        }

        /// <inheritdoc />
        public override void Encrypt(
            ReadOnlySpan<byte> plaintext,
            ReadOnlySpan<byte> nonce,
            Span<byte> ciphertext)
        {
            if (plaintext.IsEmpty)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.plaintext);
            }

            if (_disposed)
            {
                ThrowHelper.ThrowObjectDisposedException(GetType());
            }

            byte[]? arrayToReturnToPool = null;
            Aes aes = _aesPool.Get();
            try
            {
                aes.IV = nonce.ToArray();
                using ICryptoTransform encryptor = aes.CreateEncryptor();
                AesCbcHelper.Transform(encryptor, plaintext, 0, plaintext.Length, ciphertext);
            }
            catch
            {
                CryptographicOperations.ZeroMemory(ciphertext);
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

        /// <inheritdoc />
        public override void Dispose()
        {
            if (!_disposed)
            {
                _aesPool.Dispose();

                _disposed = true;
            }
        }

        public override void EncryptBlock(ref byte plaintext, ref byte ciphertext)
            => throw new NotSupportedException();

        private sealed class AesPooledPolicy : PooledObjectFactory<Aes>
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
        }
    }
}
