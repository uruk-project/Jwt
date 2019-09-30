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
    public abstract class AesNiCbcHmacDecryptor : AuthenticatedDecryptor
    {
        private readonly SymmetricJwk _hmacKey;
        private readonly SymmetricSigner _signer;

        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="AesNiCbcHmacEncryptor"/> class.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="encryptionAlgorithm"></param>
        protected AesNiCbcHmacDecryptor(SymmetricJwk key, EncryptionAlgorithm encryptionAlgorithm)
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
            _hmacKey = SymmetricJwk.FromSpan(key.K.Slice(0, keyLength), false);

            if (!_hmacKey.TryGetSigner(encryptionAlgorithm.SignatureAlgorithm, out var signer))
            {
                ThrowHelper.ThrowNotSupportedException_SignatureAlgorithm(encryptionAlgorithm.SignatureAlgorithm);
            }

            _signer = (SymmetricSigner)signer!;
        }

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