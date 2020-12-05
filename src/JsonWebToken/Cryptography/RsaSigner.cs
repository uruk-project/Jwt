// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Diagnostics;
using System.Security.Cryptography;

namespace JsonWebToken.Cryptography
{
    internal sealed class RsaSigner : Signer
    {
        private readonly ObjectPool<RSA> _rsaPool;
        private readonly HashAlgorithmName _hashAlgorithm;
        private readonly Sha2 _sha;
        private readonly int _hashSizeInBytes;
        private readonly RSASignaturePadding _signaturePadding;
        private readonly int _base64HashSizeInBytes;
        private bool _disposed;

        public RsaSigner(RsaJwk key, SignatureAlgorithm algorithm)
            : base(algorithm)
        {
            Debug.Assert(key != null);
            Debug.Assert(key.SupportSignature(algorithm));

            if (key.HasPrivateKey)
            {
                if (key.KeySizeInBits < 2048)
                {
                    ThrowHelper.ThrowArgumentOutOfRangeException_SigningKeyTooSmall(key, 2048);
                }
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

        public override bool TrySign(ReadOnlySpan<byte> data, Span<byte> destination, out int bytesWritten)
        {
            if (data.IsEmpty)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.data);
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
                return rsa.TrySignHash(hash, destination, _hashAlgorithm, _signaturePadding, out bytesWritten);
#else
                byte[] hash = new byte[_sha.HashSize];
                _sha.ComputeHash(data, hash);
                var result = rsa.SignHash(hash, _hashAlgorithm, _signaturePadding);
                bytesWritten = result.Length;
                result.CopyTo(destination);
                return true;
#endif
            }
            finally
            {
                _rsaPool.Return(rsa);
            }
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