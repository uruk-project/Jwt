// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;

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

        /// <summary>
        /// Initializes a new instance of the <see cref="AesCbcHmacEncryptor"/> class.
        /// </summary>
        /// <param name="encryptionAlgorithm"></param>
        /// <param name="encryptor"></param>
        public AesCbcHmacEncryptor(EncryptionAlgorithm encryptionAlgorithm, AesEncryptor encryptor)
        {
            Debug.Assert(encryptionAlgorithm != null);
            Debug.Assert(encryptionAlgorithm!.Category == EncryptionType.AesHmac);
            Debug.Assert(encryptionAlgorithm.SignatureAlgorithm != null);
            Debug.Assert(encryptor != null);

            _encryptionAlgorithm = encryptionAlgorithm;
            _keyLength = encryptionAlgorithm.RequiredKeySizeInBytes >> 1;
            _encryptor = encryptor!;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AesCbcHmacEncryptor"/> class.
        /// </summary>
        /// <param name="encryptionAlgorithm"></param>
        public AesCbcHmacEncryptor(EncryptionAlgorithm encryptionAlgorithm)
            : this(encryptionAlgorithm, new AesCbcEncryptor(encryptionAlgorithm))
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
            return _encryptionAlgorithm.SignatureAlgorithm.RequiredKeySizeInBits >> 2;
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

            if (associatedData.IsEmpty)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.associatedData);
            }

            try
            {
                _encryptor.Encrypt(key.Slice(_keyLength), plaintext, nonce, ciphertext);
                ComputeAuthenticationTag(key.Slice(0, _keyLength), nonce, associatedData, ciphertext, authenticationTag, out authenticationTagBytesWritten);
            }
            catch
            {
                CryptographicOperations.ZeroMemory(ciphertext);
                throw;
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
                BinaryPrimitives.WriteInt64BigEndian(bytes, associatedData.Length << 3);

                Sha2 hashAlgorithm = _encryptionAlgorithm.SignatureAlgorithm.Sha;
                Span<byte> hmacKey = stackalloc byte[hashAlgorithm.BlockSize * 2];
                Hmac hmac = new Hmac(hashAlgorithm, key, hmacKey);
                hmac.ComputeHash(macBytes, authenticationTag);
                authenticationTagBytesWritten = authenticationTag.Length >> 1;
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
}
