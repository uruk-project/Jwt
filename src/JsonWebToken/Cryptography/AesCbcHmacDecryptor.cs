// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.Buffers.Binary;

namespace JsonWebToken.Internal
{
    /// <summary>
    /// Provides authenticated encryption and decryption for AES CBC HMAC algorithm.
    /// </summary>
    public sealed class AesCbcHmacDecryptor : AuthenticatedDecryptor
    {
        private readonly AesDecryptor _decryptor;
        private readonly EncryptionAlgorithm _encryptionAlgorithm;

        /// <summary>
        /// Initializes a new instance of the <see cref="AesCbcHmacDecryptor"/> class.
        /// </summary>
        /// <param name="encryptionAlgorithm"></param>
        /// <param name="decryptor"></param>
        public AesCbcHmacDecryptor(EncryptionAlgorithm encryptionAlgorithm, AesDecryptor decryptor)
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
            _decryptor = decryptor;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AesCbcHmacDecryptor"/> class.
        /// </summary>
        /// <param name="encryptionAlgorithm"></param>
        public AesCbcHmacDecryptor(EncryptionAlgorithm encryptionAlgorithm)
            : this(encryptionAlgorithm, new AesCbcDecryptor(encryptionAlgorithm))
        {
        }

        /// <inheritdoc />
        public override bool TryDecrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> authenticationTag, Span<byte> plaintext, out int bytesWritten)
        {
            if (ciphertext.IsEmpty)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.ciphertext);
            }

            if (associatedData.IsEmpty)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.associatedData);
            }

            if (nonce.IsEmpty)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.nonce);
            }

            if (authenticationTag.IsEmpty)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.authenticationTag);
            }

            if (key.Length < _encryptionAlgorithm.RequiredKeySizeInBytes)
            {
                bytesWritten = 0;
                return false;
            }

            int keyLength = _encryptionAlgorithm.RequiredKeySizeInBits >> 4;

            var keyBytes = key;
            var aesKey = keyBytes.Slice(keyLength);
            var hashKey = keyBytes.Slice(0, keyLength);
            if (_encryptionAlgorithm.SignatureAlgorithm is null)
            {
                ThrowHelper.ThrowNotSupportedException_SignatureAlgorithm(_encryptionAlgorithm.SignatureAlgorithm);
            }

            if (VerifyAuthenticationTag(hashKey, nonce, associatedData, ciphertext, authenticationTag))
            {
                return _decryptor.TryDecrypt(aesKey, ciphertext, nonce, plaintext, out bytesWritten);
            }
            else
            {
                plaintext.Clear();
                bytesWritten = 0;
                return false;
            }
        }

        private bool VerifyAuthenticationTag(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> authenticationTag)
        {
            byte[]? byteArrayToReturnToPool = null;
            int macLength = associatedData.Length + iv.Length + ciphertext.Length + sizeof(long);
            Span<byte> macBytes = macLength <= Constants.MaxStackallocBytes
                                    ? stackalloc byte[macLength]
                                    : (byteArrayToReturnToPool = ArrayPool<byte>.Shared.Rent(macLength)).AsSpan(0, macLength);
            try
            {
                associatedData.CopyTo(macBytes);
                var bytes = macBytes.Slice(associatedData.Length);
                iv.CopyTo(bytes);
                bytes = bytes.Slice(iv.Length);
                ciphertext.CopyTo(bytes);
                bytes = bytes.Slice(ciphertext.Length);
                BinaryPrimitives.WriteInt64BigEndian(bytes, associatedData.Length << 3);
                HmacSha2 hashAlgorithm = _encryptionAlgorithm.SignatureAlgorithm!.Id switch
                {
                    Algorithms.HmacSha256 => new HmacSha256(key),
                    Algorithms.HmacSha384 => new HmacSha384(key),
                    Algorithms.HmacSha512 => new HmacSha512(key),
                    _ => new NotSupportedHmacSha(_encryptionAlgorithm.SignatureAlgorithm!)
                };
                Span<byte> hash = stackalloc byte[authenticationTag.Length * 2];
                hashAlgorithm.ComputeHash(macBytes, hash);
                return CryptographicOperations.FixedTimeEquals(authenticationTag, hash.Slice(0, authenticationTag.Length));

            }
            finally
            {
                if (byteArrayToReturnToPool != null)
                {
                    ArrayPool<byte>.Shared.Return(byteArrayToReturnToPool);
                }
            }
        }
    }
}
