// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Security.Cryptography;

namespace JsonWebToken.Internal
{
    internal sealed class AesCbcDecryptor : AesDecryptor
    {
        private readonly ObjectPool<Aes> _aesPool;
        private bool _disposed;

        public AesCbcDecryptor(ReadOnlySpan<byte> key, EncryptionAlgorithm encryptionAlgorithm)
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
        public override bool TryDecrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, Span<byte> plaintext, out int bytesWritten)
        {
            if (ciphertext.IsEmpty)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.ciphertext);
            }

            if (nonce.IsEmpty)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.nonce);
            }

            if (_disposed)
            {
                ThrowHelper.ThrowObjectDisposedException(GetType());
            }

            Aes aes = _aesPool.Get();
            try
            {
                aes.IV = nonce.ToArray();
                using (var decryptor = aes.CreateDecryptor())
                {
                    bytesWritten = AesCbcHelper.Transform(decryptor, ciphertext, 0, ciphertext.Length, plaintext);
                }

                return bytesWritten <= ciphertext.Length;
            }
            finally
            {
                _aesPool.Return(aes);
            }
        }

        public override void DecryptBlock(ref byte ciphertext, ref byte plaintext)
            => throw new NotSupportedException();

        /// <inheritdoc />
        public override void Dispose()
        {
            if (!_disposed)
            {
                _aesPool.Dispose();
                _disposed = true;
            }
        }

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
