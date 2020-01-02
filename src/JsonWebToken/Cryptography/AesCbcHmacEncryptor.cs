// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Diagnostics;
using System.Buffers.Binary;

namespace JsonWebToken.Internal
{
    /// <summary>
    /// Provides authenticated encryption and decryption for AES CBC HMAC algorithm.
    /// </summary>
    public sealed class AesCbcHmacEncryptor : AuthenticatedEncryptor
    {
        private readonly SymmetricJwk _hmacKey;
        private readonly SymmetricSigner _signer;
        private readonly AesEncryptor _encryptor;

        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="AesCbcHmacEncryptor"/> class.
        /// </summary>
        /// <param name="hmacKey"></param>
        /// <param name="encryptionAlgorithm"></param>
        /// <param name="encryptor"></param>
        public AesCbcHmacEncryptor(ReadOnlySpan<byte> hmacKey, EncryptionAlgorithm encryptionAlgorithm, AesEncryptor encryptor)
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
            if (hmacKey.Length < keyLength)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException_EncryptionKeyTooSmall(encryptionAlgorithm, encryptionAlgorithm.RequiredKeySizeInBits, hmacKey.Length >> 3);
            }

            _encryptor = encryptor;
            _hmacKey = SymmetricJwk.FromSpan(hmacKey.Slice(0, keyLength), false);
            if (!_hmacKey.TryGetSigner(encryptionAlgorithm.SignatureAlgorithm, out var signer))
            {
                ThrowHelper.ThrowNotSupportedException_SignatureAlgorithm(encryptionAlgorithm.SignatureAlgorithm);
            }

            _signer = (SymmetricSigner)signer;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AesCbcHmacEncryptor"/> class.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="encryptionAlgorithm"></param>
        public AesCbcHmacEncryptor(SymmetricJwk key, EncryptionAlgorithm encryptionAlgorithm)
        {
            if (key is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.key);
            }

            if (encryptionAlgorithm is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.encryptionAlgorithm);
            }

            if (encryptionAlgorithm.Category != EncryptionType.AesHmac)
            {
                ThrowHelper.ThrowNotSupportedException_EncryptionAlgorithm(encryptionAlgorithm);
            }

            if (key.KeySizeInBits < encryptionAlgorithm.RequiredKeySizeInBits)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException_EncryptionKeyTooSmall(key, encryptionAlgorithm, encryptionAlgorithm.RequiredKeySizeInBits, key.KeySizeInBits);
            }

            int keyLength = encryptionAlgorithm.RequiredKeySizeInBits >> 4;

            var keyBytes = key.K;
            _encryptor = new AesCbcEncryptor(keyBytes.Slice(keyLength), encryptionAlgorithm);

            _hmacKey = SymmetricJwk.FromSpan(keyBytes.Slice(0, keyLength), false);
            if (!_hmacKey.TryGetSigner(encryptionAlgorithm.SignatureAlgorithm, out var signer))
            {
                ThrowHelper.ThrowNotSupportedException_SignatureAlgorithm(encryptionAlgorithm.SignatureAlgorithm);
            }

            _signer = (SymmetricSigner)signer;
        }

        /// <inheritdoc />
        public override int GetCiphertextSize(int plaintextSize)
        {
            return (plaintextSize + 16) & ~15;
        }

        /// <inheritdoc />
        public override int GetNonceSize()
        {
            return 16;
        }

        /// <inheritdoc />
        public override int GetBase64NonceSize()
        {
            return 22;
        }

        /// <inheritdoc />
        public override int GetTagSize()
        {
            return _signer.HashSizeInBytes;
        }

        /// <inheritdoc />
        public override int GetBase64TagSize()
        {
            return _signer.Base64HashSizeInBytes;
        }

        /// <inheritdoc />
        public override void Encrypt(
            ReadOnlySpan<byte> plaintext,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> associatedData,
            Span<byte> ciphertext,
            Span<byte> authenticationTag)
        {
            if (associatedData.IsEmpty)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.associatedData);
            }

            if (_disposed)
            {
                ThrowHelper.ThrowObjectDisposedException(GetType());
            }

            try
            {
                _encryptor.Encrypt(plaintext, nonce, ciphertext);
                ComputeAuthenticationTag(nonce, associatedData, ciphertext, authenticationTag);
            }
            catch
            {
                CryptographicOperations.ZeroMemory(ciphertext);
                throw;
            }
        }

        /// <inheritdoc />
        public override void Dispose()
        {
            if (!_disposed)
            {
                _hmacKey.Dispose();
                _encryptor.Dispose();
                _disposed = true;
            }
        }

        private void ComputeAuthenticationTag(ReadOnlySpan<byte> iv, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> ciphertext, Span<byte> authenticationTag)
        {
            byte[]? arrayToReturnToPool = null;
            try
            {
                int macLength = associatedData.Length + iv.Length + ciphertext.Length + sizeof(long);
                Span<byte> macBytes = macLength <= Constants.MaxStackallocBytes
                    ? stackalloc byte[macLength]
                    : (arrayToReturnToPool = ArrayPool<byte>.Shared.Rent(macLength)).AsSpan(0, macLength);

                associatedData.CopyTo(macBytes);
                var bytes = macBytes.Slice(associatedData.Length);
                iv.CopyTo(bytes);
                bytes = bytes.Slice(iv.Length);
                ciphertext.CopyTo(bytes);
                bytes = bytes.Slice(ciphertext.Length);
                BinaryPrimitives.WriteInt64BigEndian(bytes, associatedData.Length * 8);

                _signer.TrySign(macBytes, authenticationTag, out int writtenBytes);
                Debug.Assert(writtenBytes == authenticationTag.Length);
            }
            finally
            {
                if (arrayToReturnToPool != null)
                {
                    ArrayPool<byte>.Shared.Return(arrayToReturnToPool);
                }
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
