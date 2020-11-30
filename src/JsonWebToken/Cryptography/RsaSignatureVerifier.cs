// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Security.Cryptography;

namespace JsonWebToken.Cryptography
{
    internal sealed class RsaSignatureVerifier : SignatureVerifier
    {
        private readonly ObjectPool<RSA> _rsaPool;
        private readonly HashAlgorithmName _hashAlgorithm;
        private readonly Sha2 _sha;
        private readonly int _hashSizeInBytes;
        private readonly RSASignaturePadding _signaturePadding;
        private readonly int _base64HashSizeInBytes;
        private bool _disposed;

        public RsaSignatureVerifier(RsaJwk key, SignatureAlgorithm algorithm)
            : base(algorithm)
        {
            if (key is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.key);
            }

            if (!key.SupportSignature(algorithm))
            {
                ThrowHelper.ThrowNotSupportedException_SignatureAlgorithm(algorithm, key);
            }

            if (key.KeySizeInBits < 1024)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException_SigningKeyTooSmall(key, 1024);
            }

            _hashAlgorithm = algorithm.HashAlgorithm;
            _sha = algorithm.Sha;
            _signaturePadding = RsaHelper.GetPadding(algorithm);

            _hashSizeInBytes = key.KeySizeInBits >> 3;
            _base64HashSizeInBytes = Base64Url.GetArraySizeRequiredToEncode(_hashSizeInBytes);
            _rsaPool = new ObjectPool<RSA>(new RsaObjectPoolPolicy(key.ExportParameters()));
        }

        public override int HashSizeInBytes => _hashSizeInBytes;

        public override int Base64HashSizeInBytes => _base64HashSizeInBytes;

        public override bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
        {
            if (data.IsEmpty)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.data);
            }

            if (signature.IsEmpty)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.signature);
            }

            if (_disposed)
            {
                ThrowHelper.ThrowObjectDisposedException(GetType());
            }

            var rsa = _rsaPool.Get();
            try
            {
#if SUPPORT_SPAN_CRYPTO
                Span<byte> hash = stackalloc byte[_sha.HashSize];
                _sha.ComputeHash(data, hash);
                return rsa.VerifyHash(hash, signature, _hashAlgorithm, _signaturePadding);
#else
                byte[] hash = new byte[_sha.HashSize];
                _sha.ComputeHash(data, hash);
                return rsa.VerifyHash(hash, signature.ToArray(), _hashAlgorithm, _signaturePadding);
#endif
            }
            finally
            {
                _rsaPool.Return(rsa);
            }
        }

        public override bool VerifyHalf(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
        {
            throw new NotImplementedException();
        }

        protected override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    _rsaPool.Dispose();
                }

                _disposed = true;
            }
        }
    }
}