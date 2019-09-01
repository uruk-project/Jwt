﻿// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

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
#if !NETSTANDARD2_0 && !NET461
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
        public override bool TryUnwrapKey(ReadOnlySpan<byte> key, Span<byte> destination, JwtHeader header, out int bytesWritten)
        {
            if (key.IsEmpty)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.key);
            }

            if (header == null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.header);
            }

            if (_disposed)
            {
                ThrowHelper.ThrowObjectDisposedException(GetType());
            }

            try
            {
#if !NETSTANDARD2_0 && !NET461
                return _rsa.TryDecrypt(key, destination, _padding, out bytesWritten);
#else
                var result = _rsa.Decrypt(key.ToArray(), _padding);
                bytesWritten = result.Length;
                result.CopyTo(destination);

                return true;
#endif
            }
            catch (CryptographicException)
            {
                bytesWritten = 0;
                return false;
            }
        }

        /// <inheritsdoc />
        public override Jwk WrapKey(Jwk? staticKey, JwtObject header, Span<byte> destination)
        {
            if (_disposed)
            {
                ThrowHelper.ThrowObjectDisposedException(GetType());
            }

            var cek = SymmetricKeyHelper.CreateSymmetricKey(EncryptionAlgorithm, staticKey);
#if !NETSTANDARD2_0 && !NET461
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
        public override int GetKeyUnwrapSize(int wrappedKeySize)
        {
            return EncryptionAlgorithm.RequiredKeySizeInBytes;
        }

        /// <inheritsdoc />
        public override int GetKeyWrapSize()
        {
            return Key.KeySizeInBits >> 3;
        }

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
