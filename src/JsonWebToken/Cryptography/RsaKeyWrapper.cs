// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Diagnostics;
using System.Security.Cryptography;

namespace JsonWebToken.Cryptography
{
    /// <summary>
    /// Provides RSA key wrapping and key unwrapping services.
    /// </summary>
    internal sealed class RsaKeyWrapper : KeyWrapper
    {
        private readonly RsaJwk _key;
        private readonly RSA _rsa;
        private readonly RSAEncryptionPadding _padding;
        private bool _disposed;

        public RsaKeyWrapper(RsaJwk key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
            : base(encryptionAlgorithm, algorithm)
        {
            Debug.Assert(key.SupportKeyManagement(algorithm));
            Debug.Assert(algorithm.Category == AlgorithmCategory.Rsa);
            _key = key;
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
            _padding = algorithm.Id switch
            {
                AlgorithmId.RsaOaep => RSAEncryptionPadding.OaepSHA1,
                AlgorithmId.Rsa1_5 => RSAEncryptionPadding.Pkcs1,
                AlgorithmId.RsaOaep256 => RSAEncryptionPadding.OaepSHA256,
                AlgorithmId.RsaOaep384 => RSAEncryptionPadding.OaepSHA384,
                AlgorithmId.RsaOaep512 => RSAEncryptionPadding.OaepSHA512,
                _ => throw ThrowHelper.CreateNotSupportedException_AlgorithmForKeyWrap(algorithm)
            };
        }

        /// <inheritsdoc />
        public override SymmetricJwk WrapKey(Jwk? staticKey, JwtHeader header, Span<byte> destination)
        {
            Debug.Assert(header != null);
            if (_disposed)
            {
                ThrowHelper.ThrowObjectDisposedException(GetType());
            }

            var cek = CreateSymmetricKey(EncryptionAlgorithm, (SymmetricJwk?)staticKey);
#if SUPPORT_SPAN_CRYPTO
            if (!_rsa.TryEncrypt(cek.AsSpan(), destination, _padding, out int bytesWritten))
            {
                ThrowHelper.ThrowCryptographicException_KeyWrapFailed();
            }

            Debug.Assert(bytesWritten == destination.Length);
#else
            var result = _rsa.Encrypt(cek.ToArray(), _padding);
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
            => _key.KeySizeInBits >> 3;

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
