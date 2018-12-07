// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;

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
            if (key.K == null)
            {
                Errors.ThrowMalformedKey(key);
            }
        }

        /// <inheritsdoc />
        public override int GetKeyUnwrapSize(int wrappedKeySize)
        {
            return GetKeyUnwrappedSize(wrappedKeySize, Algorithm);
        }

        /// <inheritsdoc />
        public override int GetKeyWrapSize()
        {
            return GetKeyWrappedSize(EncryptionAlgorithm);
        }

        /// <inheritsdoc />
        public override bool TryUnwrapKey(ReadOnlySpan<byte> keyBytes, Span<byte> destination, JwtHeader header, out int bytesWritten)
        {
            if (_disposed)
            {
                Errors.ThrowObjectDisposed(GetType());
            }

            Span<byte> nonce = stackalloc byte[Base64Url.GetArraySizeRequiredToDecode(header.IV.Length)];
            Span<byte> tag = stackalloc byte[Base64Url.GetArraySizeRequiredToDecode(header.Tag.Length)];
            try
            {
                Base64Url.Base64UrlDecode(header.IV, nonce);
                Base64Url.Base64UrlDecode(header.Tag, tag);
                using (var aesGcm = new AesGcm(Key.ToByteArray()))
                {
                    aesGcm.Decrypt(nonce, keyBytes, tag, destination);
                    bytesWritten = destination.Length;

                    return true;
                }
            }
            catch
            {
                return Errors.TryWriteError(out bytesWritten);
            }
        }

        /// <inheritsdoc />
        public override bool TryWrapKey(Jwk staticKey, Dictionary<string, object> header, Span<byte> destination, out Jwk contentEncryptionKey, out int bytesWritten)
        {
            if (_disposed)
            {
                Errors.ThrowObjectDisposed(GetType());
            }

            contentEncryptionKey = SymmetricKeyHelper.CreateSymmetricKey(EncryptionAlgorithm, staticKey);
            Span<byte> nonce = stackalloc byte[IVSize];
            Span<byte> tag = stackalloc byte[TagSize];

            try
            {
                using (var aesGcm = new AesGcm(Key.ToByteArray()))
                {
                    aesGcm.Encrypt(nonce, contentEncryptionKey.ToByteArray(), destination, tag);
                    bytesWritten = destination.Length;

                    header[HeaderParameters.IV] = Base64Url.Base64UrlEncode(nonce);
                    header[HeaderParameters.Tag] = Base64Url.Base64UrlEncode(tag);

                    return true;
                }
            }
            catch
            {
                contentEncryptionKey = null;
                return Errors.TryWriteError(out bytesWritten);
            }
        }

        /// <inheritsdoc />
        protected override void Dispose(bool disposing)
        {
            _disposed = true;
        }

        private static int GetKeyUnwrappedSize(int wrappedKeySize, KeyManagementAlgorithm algorithm)
        {
            return wrappedKeySize - 8;
        }

        private static int GetKeyWrappedSize(EncryptionAlgorithm encryptionAlgorithm)
        {
            return encryptionAlgorithm.KeyWrappedSizeInBytes;
        }
    }
}
