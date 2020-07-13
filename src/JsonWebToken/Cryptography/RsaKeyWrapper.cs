// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Security.Cryptography;

namespace JsonWebToken.Internal
{
    /// <summary>
    /// Provides RSA key wrapping and key unwrapping services.
    /// </summary>
    internal sealed class RsaKeyWrapper : KeyWrapper
    {
        private readonly RSA _rsa;
        private readonly RSAEncryptionPadding _padding;
        private bool _disposed;

        public RsaKeyWrapper(RsaJwk key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm contentEncryptionAlgorithm)
            : base(key, encryptionAlgorithm, contentEncryptionAlgorithm)
        {
#if SUPPORT_SPAN_CRYPTO
            _rsa = RSA.Create(key.ExportParameters());
#else
            _rsa = RSA.Create();
            _rsa.ImportParameters(key.ExportParameters());
#endif

            if (contentEncryptionAlgorithm == KeyManagementAlgorithm.RsaOaep)
            {
                _padding = RSAEncryptionPadding.OaepSHA1;
            }
            else if (contentEncryptionAlgorithm == KeyManagementAlgorithm.RsaPkcs1)
            {
                _padding = RSAEncryptionPadding.Pkcs1;
            }
            else if (contentEncryptionAlgorithm == KeyManagementAlgorithm.RsaOaep256)
            {
                _padding = RSAEncryptionPadding.OaepSHA256;
            }
            else if (contentEncryptionAlgorithm == KeyManagementAlgorithm.RsaOaep384)
            {
                _padding = RSAEncryptionPadding.OaepSHA384;
            }
            else if (contentEncryptionAlgorithm == KeyManagementAlgorithm.RsaOaep512)
            {
                _padding = RSAEncryptionPadding.OaepSHA512;
            }
            else
            {
                ThrowHelper.ThrowNotSupportedException_AlgorithmForKeyWrap(contentEncryptionAlgorithm);
                _padding = RSAEncryptionPadding.CreateOaep(new HashAlgorithmName()); // will never occur
            }
        }

        /// <inheritsdoc />
        public override Jwk WrapKey(Jwk? staticKey, JwtObject header, Span<byte> destination)
        {
            if (_disposed)
            {
                ThrowHelper.ThrowObjectDisposedException(GetType());
            }

            var cek = CreateSymmetricKey(EncryptionAlgorithm, staticKey);
#if SUPPORT_SPAN_CRYPTO
            if (!_rsa.TryEncrypt(cek.AsSpan(), destination, _padding, out int bytesWritten) || bytesWritten != destination.Length)
            {
                ThrowHelper.ThrowCryptographicException_KeyWrapFailed();
            }
#else
            var result = _rsa.Encrypt(cek.AsSpan().ToArray(), _padding);
            if (destination.Length < result.Length)
            {
                ThrowHelper.ThrowCryptographicException_KeyWrapFailed();
            }

            result.CopyTo(destination);
#endif

            return cek;
        }

        /// <inheritsdoc />
        public override int GetKeyWrapSize()
            => Key.KeySizeInBits >> 3;

        /// <inheritsdoc />
        protected override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    _rsa.Dispose();
                }

                _disposed = true;
            }
        }
    }
}
