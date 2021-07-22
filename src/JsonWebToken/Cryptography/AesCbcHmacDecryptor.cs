// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;

namespace JsonWebToken.Cryptography
{
    /// <summary>Provides authenticated encryption and decryption for AES CBC HMAC algorithm.</summary>
    internal sealed class AesCbcHmacDecryptor : AuthenticatedDecryptor
    {
        private readonly AesDecryptor _decryptor;
        private readonly EncryptionAlgorithm _encryptionAlgorithm;

        /// <summary>Initializes a new instance of the <see cref="AesCbcHmacDecryptor"/> class.</summary>
        public AesCbcHmacDecryptor(EncryptionAlgorithm encryptionAlgorithm, AesDecryptor decryptor)
        {
            Debug.Assert(encryptionAlgorithm != null);
            Debug.Assert(encryptionAlgorithm!.Category == EncryptionType.AesHmac);
            Debug.Assert(encryptionAlgorithm!.SignatureAlgorithm != null);
            Debug.Assert(decryptor != null);

            _encryptionAlgorithm = encryptionAlgorithm;
            _decryptor = decryptor;
        }

        /// <summary>Initializes a new instance of the <see cref="AesCbcHmacDecryptor"/> class.</summary>
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

            int requiredKeyLength = _encryptionAlgorithm.RequiredKeySizeInBytes >> 1;
            if (key.Length >= requiredKeyLength)
            {
                var aesKey = key.Slice(requiredKeyLength);
                var hashKey = key.Slice(0, requiredKeyLength);
                if (VerifyAuthenticationTag(hashKey, nonce, associatedData, ciphertext, authenticationTag))
                {
                    return _decryptor.TryDecrypt(aesKey, ciphertext, nonce, plaintext, out bytesWritten);
                }
            }

            bytesWritten = 0;
            return false;
        }

        private bool VerifyAuthenticationTag(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> authenticationTag)
        {
            byte[]? byteArrayToReturnToPool = null;
            int macLength = associatedData.Length + iv.Length + ciphertext.Length + sizeof(long);
            Span<byte> macBytes = macLength <= Constants.MaxStackallocBytes
                                    ? stackalloc byte[Constants.MaxStackallocBytes]
                                    : (byteArrayToReturnToPool = ArrayPool<byte>.Shared.Rent(macLength));
            try
            {
                macBytes = macBytes.Slice(0, macLength);
                associatedData.CopyTo(macBytes);
                var bytes = macBytes.Slice(associatedData.Length);
                iv.CopyTo(bytes);
                bytes = bytes.Slice(iv.Length);
                ciphertext.CopyTo(bytes);
                bytes = bytes.Slice(ciphertext.Length);
                BinaryPrimitives.WriteInt64BigEndian(bytes, associatedData.Length << 3);

                Sha2 hashAlgorithm = _encryptionAlgorithm.SignatureAlgorithm.Sha;
                Span<byte> hmacKey = stackalloc byte[Sha2.BlockSizeStackallocThreshold * 2].Slice(0, hashAlgorithm.BlockSize * 2); 
                Hmac hmac = new Hmac(hashAlgorithm, key, hmacKey);
                Span<byte> hash = stackalloc byte[AuthenticatedEncryptor.TagSizeStackallocThreshold].Slice(0, authenticationTag.Length * 2);
                hmac.ComputeHash(macBytes, hash);
                CryptographicOperations.ZeroMemory(hmacKey);

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
