// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

#if SUPPORT_AESGCM
using System;
using System.Security.Cryptography;

namespace JsonWebToken.Cryptography
{
    internal sealed class AesGcmKeyWrapper : KeyWrapper
    {
        private const int IVSize = 12;
        private const int TagSize = 16;

        private bool _disposed;

        public AesGcmKeyWrapper(SymmetricJwk key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
            : base(key, encryptionAlgorithm, algorithm)
        {
            if (algorithm.Category != AlgorithmCategory.AesGcm)
            {
                ThrowHelper.ThrowNotSupportedException_AlgorithmForKeyWrap(algorithm);
            }
        }

        /// <inheritsdoc />
        public override int GetKeyWrapSize()
            => GetKeyWrapSize(EncryptionAlgorithm);

        public static int GetKeyWrapSize(EncryptionAlgorithm encryptionAlgorithm)
            => encryptionAlgorithm.RequiredKeySizeInBytes;

        /// <inheritsdoc />
        public override SymmetricJwk WrapKey(Jwk? staticKey, JwtHeader header, Span<byte> destination)
        {
            if (_disposed)
            {
                ThrowHelper.ThrowObjectDisposedException(GetType());
            }

            var cek = CreateSymmetricKey(EncryptionAlgorithm, (SymmetricJwk?)staticKey);
            Span<byte> nonce = stackalloc byte[IVSize];
            Span<byte> tag = stackalloc byte[TagSize];

            using (var aesGcm = new AesGcm(Key.AsSpan()))
            {
                var keyBytes = cek.AsSpan();
                if (destination.Length > keyBytes.Length)
                {
                    destination = destination.Slice(0, keyBytes.Length);
                }

                aesGcm.Encrypt(nonce, keyBytes, destination, tag);

                // TODO : Avoid string allocation
                header.Add(JwtHeaderParameterNames.IV, Utf8.GetString( Base64Url.Encode(nonce)));
                header.Add(JwtHeaderParameterNames.Tag, Utf8.GetString(Base64Url.Encode(tag)));
            }

            return cek;
        }

        /// <inheritsdoc />
        protected override void Dispose(bool disposing)
        {
            _disposed = true;
        }
    }
}
#endif