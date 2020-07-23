// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace JsonWebToken.Internal
{
    /// <summary>
    /// Provides authenticated encryption and decryption for AES CBC HMAC algorithm.
    /// </summary>
    internal sealed class AesCbcHmacEncryptor : AuthenticatedEncryptor
    {
        private readonly AesEncryptor _encryptor;
        private readonly EncryptionAlgorithm _encryptionAlgorithm;
        private readonly int _keyLength;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="AesCbcHmacEncryptor"/> class.
        /// </summary>
        /// <param name="encryptionAlgorithm"></param>
        /// <param name="encryptor"></param>
        public AesCbcHmacEncryptor(EncryptionAlgorithm encryptionAlgorithm, AesEncryptor encryptor)
        {
            if (encryptionAlgorithm is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.encryptionAlgorithm);
            }

            if (encryptionAlgorithm.Category != EncryptionType.AesHmac)
            {
                ThrowHelper.ThrowNotSupportedException_EncryptionAlgorithm(encryptionAlgorithm);
            }

            _encryptionAlgorithm = encryptionAlgorithm;

            _keyLength = encryptionAlgorithm.RequiredKeySizeInBytes >> 1;
            _encryptor = encryptor;
            if (encryptionAlgorithm.SignatureAlgorithm is null)
            {
                ThrowHelper.ThrowNotSupportedException_SignatureAlgorithm(encryptionAlgorithm.SignatureAlgorithm);
            }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AesCbcHmacEncryptor"/> class.
        /// </summary>
        /// <param name="encryptionAlgorithm"></param>
        public AesCbcHmacEncryptor(EncryptionAlgorithm encryptionAlgorithm)
            :this(encryptionAlgorithm, new AesCbcEncryptor(encryptionAlgorithm))
        {
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
            return _encryptionAlgorithm.SignatureAlgorithm!.RequiredKeySizeInBits >> 2;
        }

        /// <inheritdoc />
        public override int GetBase64TagSize()
        {
            return Base64Url.GetArraySizeRequiredToEncode(_encryptionAlgorithm.SignatureAlgorithm!.RequiredKeySizeInBits / 2 * 8);
        }

        /// <inheritdoc />
        public override void Encrypt(
            ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> plaintext,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> associatedData,
            Span<byte> ciphertext,
            Span<byte> authenticationTag,
            out int authenticationTagBytesWritten)
        {

            if (key.Length < _encryptionAlgorithm.RequiredKeySizeInBytes)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException_EncryptionKeyTooSmall(_encryptionAlgorithm, _encryptionAlgorithm.RequiredKeySizeInBits, key.Length << 3);
            }

            var keyBytes = key;
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
                _encryptor.Encrypt(keyBytes.Slice(_keyLength), plaintext, nonce, ciphertext);
                ComputeAuthenticationTag(key.Slice(0, _keyLength), nonce, associatedData, ciphertext, authenticationTag, out authenticationTagBytesWritten);
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
                _disposed = true;
            }
        }

        private void ComputeAuthenticationTag(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> ciphertext, Span<byte> authenticationTag, out int authenticationTagBytesWritten)
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

                HmacSha2 hashAlgorithm = _encryptionAlgorithm.SignatureAlgorithm!.Id switch
                {
                    Algorithms.HmacSha256 => new HmacSha256(key),
                    Algorithms.HmacSha384 => new HmacSha384(key),
                    Algorithms.HmacSha512 => new HmacSha512(key),
                    _ => new NotSupportedHmacSha(_encryptionAlgorithm.SignatureAlgorithm!)
                };
                hashAlgorithm.ComputeHash(macBytes, authenticationTag);
                authenticationTagBytesWritten = authenticationTag.Length / 2;
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
