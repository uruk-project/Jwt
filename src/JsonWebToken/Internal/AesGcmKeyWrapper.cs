// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.
#if NETCOREAPP3_0
using System;
using System.Security.Cryptography;

namespace JsonWebToken.Internal
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
        public override int GetKeyUnwrapSize(int wrappedKeySize)
        {
            return wrappedKeySize;
        }

        /// <inheritsdoc />
        public override int GetKeyWrapSize() => GetKeyWrapSize(EncryptionAlgorithm);

        public static int GetKeyWrapSize(EncryptionAlgorithm encryptionAlgorithm) => encryptionAlgorithm.RequiredKeySizeInBytes;

        /// <inheritsdoc />
        public override bool TryUnwrapKey(ReadOnlySpan<byte> keyBytes, Span<byte> destination, JwtHeader header, out int bytesWritten)
        {
            if (_disposed)
            {
                ThrowHelper.ThrowObjectDisposedException(GetType());
            }

            Span<byte> nonce = stackalloc byte[Base64Url.GetArraySizeRequiredToDecode(header.IV.Length)];
            Span<byte> tag = stackalloc byte[Base64Url.GetArraySizeRequiredToDecode(header.Tag.Length)];
            try
            {
                Base64Url.Decode(header.IV, nonce);
                Base64Url.Decode(header.Tag, tag);
                using (var aesGcm = new AesGcm(Key.AsSpan()))
                {
                    aesGcm.Decrypt(nonce, keyBytes, tag, destination);
                    bytesWritten = destination.Length;

                    return true;
                }
            }
            catch
            {
                return ThrowHelper.TryWriteError(out bytesWritten);
            }
        }

        /// <inheritsdoc />
        public override void WrapKey(Jwk staticKey, JwtObject header, Span<byte> destination, out Jwk contentEncryptionKey, out int bytesWritten)
        {
            if (_disposed)
            {
                ThrowHelper.ThrowObjectDisposedException(GetType());
            }

            var cek = SymmetricKeyHelper.CreateSymmetricKey(EncryptionAlgorithm, staticKey);
            Span<byte> nonce = stackalloc byte[IVSize];
            Span<byte> tag = stackalloc byte[TagSize];

            using (var aesGcm = new AesGcm(Key.AsSpan()))
            {
                aesGcm.Encrypt(nonce, cek.AsSpan(), destination, tag);

                header.Add(new JwtProperty(HeaderParameters.IVUtf8, Base64Url.Encode(nonce)));
                header.Add(new JwtProperty(HeaderParameters.TagUtf8, Base64Url.Encode(tag)));
            }

            bytesWritten = destination.Length;
            contentEncryptionKey = cek;
        }

        /// <inheritsdoc />
        protected override void Dispose(bool disposing)
        {
            _disposed = true;
        }
    }
}
#endif