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
#if NET461 || NET47
            _rsa = new RSACng();
#else
            _rsa = RSA.Create();
#endif
            _rsa.ImportParameters(key.ExportParameters());
#endif
            _padding = contentEncryptionAlgorithm.Id switch
            {
                Algorithms.RsaOaep => RSAEncryptionPadding.OaepSHA1,
                Algorithms.RsaPkcs1 => RSAEncryptionPadding.Pkcs1,
                Algorithms.RsaOaep256 => RSAEncryptionPadding.OaepSHA256,
                Algorithms.RsaOaep384 => RSAEncryptionPadding.OaepSHA384,
                Algorithms.RsaOaep512 => RSAEncryptionPadding.OaepSHA512,
                _ => throw ThrowHelper.CreateNotSupportedException_AlgorithmForKeyWrap(contentEncryptionAlgorithm)
            };
        }

        /// <inheritsdoc />
        public override SymmetricJwk WrapKey(Jwk? staticKey, JwtObject header, Span<byte> destination)
        {
            if (_disposed)
            {
                ThrowHelper.ThrowObjectDisposedException(GetType());
            }

            var cek = CreateSymmetricKey(EncryptionAlgorithm, (SymmetricJwk?)staticKey);
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
        public override SymmetricJwk WrapKey(Jwk? staticKey, JwtHeaderX header, Span<byte> destination)
        {
            if (_disposed)
            {
                ThrowHelper.ThrowObjectDisposedException(GetType());
            }

            var cek = CreateSymmetricKey(EncryptionAlgorithm, (SymmetricJwk?)staticKey);
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
