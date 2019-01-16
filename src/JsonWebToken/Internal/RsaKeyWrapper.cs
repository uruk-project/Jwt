// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
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
#if !NETSTANDARD2_0
            _rsa = RSA.Create(key.ExportParameters());
#else
            _rsa = RSA.Create();
            _rsa.ImportParameters(key.ExportParameters());
#endif

            if (contentEncryptionAlgorithm == KeyManagementAlgorithm.RsaOaep)
            {
                _padding = RSAEncryptionPadding.OaepSHA1;
            }
            else if (contentEncryptionAlgorithm == KeyManagementAlgorithm.RsaOaep256
                || contentEncryptionAlgorithm == KeyManagementAlgorithm.RsaPkcs1)
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
                Errors.ThrowNotSupportedAlgorithmForKeyWrap(contentEncryptionAlgorithm);
            }
        }

        /// <inheritsdoc />
        public override bool TryUnwrapKey(ReadOnlySpan<byte> keyBytes, Span<byte> destination, JwtHeader header, out int bytesWritten)
        {
            if (keyBytes.IsEmpty)
            {
                throw new ArgumentNullException(nameof(keyBytes));
            }

            if (header == null)
            {
                throw new ArgumentNullException(nameof(header));
            }

            if (_disposed)
            {
                Errors.ThrowObjectDisposed(GetType());
            }

#if !NETSTANDARD2_0
            return _rsa.TryDecrypt(keyBytes, destination, _padding, out bytesWritten);
#else
            var result = _rsa.Decrypt(keyBytes.ToArray(), _padding);
            bytesWritten = result.Length;
            result.CopyTo(destination);

            return true;
#endif
        }

        /// <inheritsdoc />
        public override bool TryWrapKey(Jwk staticKey, Dictionary<string, object> header, Span<byte> destination, out Jwk contentEncryptionKey, out int bytesWritten)
        {
            if (_disposed)
            {
                Errors.ThrowObjectDisposed(GetType());
            }

            contentEncryptionKey = SymmetricKeyHelper.CreateSymmetricKey(EncryptionAlgorithm, staticKey);
#if !NETSTANDARD2_0
            return _rsa.TryEncrypt(contentEncryptionKey.ToByteArray(), destination, _padding, out bytesWritten);
#else
            var result = _rsa.Encrypt(contentEncryptionKey.ToByteArray(), _padding);
            result.CopyTo(destination);
            bytesWritten = result.Length;
            return true;
#endif
        }

        /// <inheritsdoc />
        public override int GetKeyUnwrapSize(int wrappedKeySize)
        {
            return Key.KeySizeInBits >> 3 > EncryptionAlgorithm.RequiredKeySizeInBytes 
                ? Key.KeySizeInBits >> 3 
                : EncryptionAlgorithm.RequiredKeySizeInBytes;
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
