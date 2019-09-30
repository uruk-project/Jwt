// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

#if NETCOREAPP3_0
using System;
using System.Runtime.Intrinsics.X86;

namespace JsonWebToken.Internal
{
    /// <summary>
    /// Provides AES encryption with CBC, PKCS#7 padding and HMAC-SHA256
    /// </summary>
    public abstract class AesNiCbcHmacEncryptor : AuthenticatedEncryptor
    {
        private readonly SymmetricJwk _hmacKey;
        private readonly SymmetricSigner _signer;
        protected readonly byte[] _expandedKey;

        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="AesNiCbcHmacEncryptor"/> class.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="encryptionAlgorithm"></param>
        protected AesNiCbcHmacEncryptor(SymmetricJwk key, EncryptionAlgorithm encryptionAlgorithm)
        {
            if (!Aes.IsSupported)
            {
                ThrowHelper.ThrowNotSupportedException_RequireAesNi();
            }

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

        /// <summary>
        /// Expands the key into a number of separate round keys.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        protected abstract byte[] ExpandKey(ReadOnlySpan<byte> key);

        /// <inheritsdoc />
        public override void Dispose()
        {
            if (!_disposed)
            {
                _signer!.Dispose();
                _hmacKey.Dispose();
                _disposed = true;
            }
        }

        /// <inheritsdoc />
        public override int GetCiphertextSize(int plaintextSize) => (plaintextSize + 16) & ~15;

        /// <inheritsdoc />
        public override int GetNonceSize() => 16;

        /// <inheritsdoc />
        public override int GetTagSize() => _signer.HashSizeInBytes;

        /// <inheritsdoc />
        public override int GetBase64NonceSize() => 22;

        /// <inheritsdoc />
        public override int GetBase64TagSize() => _signer.Base64HashSizeInBytes;

        /// <summary>
        /// Computes the <paramref name="authenticationTag"/>.
        /// </summary>
        /// <param name="iv"></param>
        /// <param name="associatedData"></param>
        /// <param name="ciphertext"></param>
        /// <param name="authenticationTag"></param>
        protected void ComputeAuthenticationTag(ReadOnlySpan<byte> iv, ReadOnlySpan<byte> associatedData, Span<byte> ciphertext, Span<byte> authenticationTag)
        {
            AesHmacHelper.ComputeAuthenticationTag(_signer, iv, associatedData, ciphertext, authenticationTag);
        }

        /// <summary>
        /// Verify the <paramref name="authenticationTag"/>.
        /// </summary>
        /// <param name="iv"></param>
        /// <param name="associatedData"></param>
        /// <param name="ciphertext"></param>
        /// <param name="authenticationTag"></param>
        /// <returns></returns>
        protected bool VerifyAuthenticationTag(ReadOnlySpan<byte> iv, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> authenticationTag)
        {
            return AesHmacHelper.VerifyAuthenticationTag(_signer, iv, associatedData, ciphertext, authenticationTag);
        }
    }
}
#endif