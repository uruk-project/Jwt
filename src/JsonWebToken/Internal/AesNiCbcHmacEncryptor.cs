// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

#if NETCOREAPP3_0
using System;
using System.Buffers;
using System.Buffers.Binary;
using AesNi = System.Runtime.Intrinsics.X86.Aes;
using System.Runtime.CompilerServices;

namespace JsonWebToken.Internal
{
    public abstract class AesNiCbcHmacEncryptor : AuthenticatedEncryptor
    {
        private readonly SymmetricJwk _hmacKey;
        private readonly SymmetricSigner _signer;
        protected readonly AesCbcHmacEncryptor? _fallbackEncryptor;
        protected readonly byte[] _expandedKey;

        private bool _disposed;

        protected AesNiCbcHmacEncryptor(SymmetricJwk key, EncryptionAlgorithm encryptionAlgorithm)
        {
            if (AesNi.IsSupported)
            {
                if (key is null)
                {
                    ThrowHelper.ThrowArgumentNullException(ExceptionArgument.key);
                }

                int keyLength = encryptionAlgorithm.RequiredKeySizeInBits >> 4;
                var keyBytes = key.K;
                var aesKey = keyBytes.Slice(keyLength).ToArray();
                _hmacKey = SymmetricJwk.FromSpan(keyBytes.Slice(0, keyLength), false);

                if (!_hmacKey.TryGetSigner(encryptionAlgorithm.SignatureAlgorithm, out var signer))
                {
                    ThrowHelper.ThrowNotSupportedException_SignatureAlgorithm(encryptionAlgorithm.SignatureAlgorithm);
                }

                _expandedKey = ExpandKey(aesKey);
                _signer = (SymmetricSigner)signer!;
            }
            else
            {
                _fallbackEncryptor = new AesCbcHmacEncryptor(key, encryptionAlgorithm);
            }
        }

        protected abstract byte[] ExpandKey(ReadOnlySpan<byte> key);

        public override void Dispose()
        {
            if (!_disposed)
            {
                _disposed = true;
                if (AesNi.IsSupported)
                {
                    _signer!.Dispose();
                    _hmacKey.Dispose();
                }
                else
                {

                    _fallbackEncryptor!.Dispose();
                }
            }
        }

        public override int GetCiphertextSize(int plaintextSize) => (plaintextSize + 16) & ~15;

        public override int GetNonceSize() => 16;

        public override int GetTagSize() => _signer.HashSizeInBytes;

        public override int GetBase64NonceSize() => 22;

        public override int GetBase64TagSize() => _signer.Base64HashSizeInBytes;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        protected static void ApplyPadding(ReadOnlySpan<byte> remainingBytes, Span<byte> lastBlock)
        {
            remainingBytes.CopyTo(lastBlock);
            lastBlock.Slice(remainingBytes.Length).Fill((byte)remainingBytes.Length);
        }

        protected void SignData(ReadOnlySpan<byte> iv, ReadOnlySpan<byte> associatedData, Span<byte> ciphertext, Span<byte> authenticationTag)
        {
            AesCbcHmacEncryptor.AddAuthenticationTag(_signer, iv, associatedData, ciphertext, authenticationTag);
        }

        protected bool ValidateSignature(ReadOnlySpan<byte> iv, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> authenticationTag)
        {
            byte[]? byteArrayToReturnToPool = null;
            int macLength = associatedData.Length + iv.Length + ciphertext.Length + sizeof(long);
            Span<byte> macBytes = macLength <= Constants.MaxStackallocBytes
                                    ? stackalloc byte[macLength]
                                    : (byteArrayToReturnToPool = ArrayPool<byte>.Shared.Rent(macLength)).AsSpan(0, macLength);
            try
            {
                associatedData.CopyTo(macBytes);
                iv.CopyTo(macBytes.Slice(associatedData.Length));
                ciphertext.CopyTo(macBytes.Slice(associatedData.Length + iv.Length));
                BinaryPrimitives.WriteInt64BigEndian(macBytes.Slice(associatedData.Length + iv.Length + ciphertext.Length), associatedData.Length * 8);
                if (!_signer.Verify(macBytes, authenticationTag))
                {
                    return false;
                }
            }
            finally
            {
                if (byteArrayToReturnToPool != null)
                {
                    ArrayPool<byte>.Shared.Return(byteArrayToReturnToPool);
                }
            }

            return true;
        }
    }
}
#endif