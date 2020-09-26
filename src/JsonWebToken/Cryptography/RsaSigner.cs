// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Security.Cryptography;
using JsonWebToken.Internal;

namespace JsonWebToken
{
    internal sealed class RsaSigner : Signer
    {
        private readonly ObjectPool<RSA> _rsaPool;
        private readonly HashAlgorithmName _hashAlgorithm;
        private readonly Sha2 _sha;
        private readonly int _hashSizeInBytes;
        private readonly RSASignaturePadding _signaturePadding;
        private readonly int _base64HashSizeInBytes;
        private readonly bool _canOnlyVerify;
        private bool _disposed;

        public RsaSigner(RsaJwk key, SignatureAlgorithm algorithm)
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

            if (key.HasPrivateKey)
            {
                if (key.KeySizeInBits < 2048)
                {
                    ThrowHelper.ThrowArgumentOutOfRangeException_SigningKeyTooSmall(key, 2048);
                }

                _canOnlyVerify = false;
            }
            else
            {
                if (key.KeySizeInBits < 1024)
                {
                    ThrowHelper.ThrowArgumentOutOfRangeException_SigningKeyTooSmall(key, 1024);
                }

                _canOnlyVerify = true;
            }

            _hashAlgorithm = algorithm.HashAlgorithm;
            _sha = algorithm.Sha;
            _signaturePadding = algorithm.Id switch
            {
                Algorithms.RsaSha256 => RSASignaturePadding.Pkcs1,
                Algorithms.RsaSha384 => RSASignaturePadding.Pkcs1,
                Algorithms.RsaSha512 => RSASignaturePadding.Pkcs1,
                Algorithms.RsaSsaPssSha256 => RSASignaturePadding.Pss,
                Algorithms.RsaSsaPssSha384 => RSASignaturePadding.Pss,
                Algorithms.RsaSsaPssSha512 => RSASignaturePadding.Pss,
                _ => throw ThrowHelper.CreateNotSupportedException_Algorithm(algorithm)
            };

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

            if (_canOnlyVerify)
            {
                ThrowHelper.ThrowInvalidOperationException_RequirePrivateKey();
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
                return rsa.VerifyData(data, signature, _hashAlgorithm, _signaturePadding);
#else
                return rsa.VerifyData(data.ToArray(), signature.ToArray(), _hashAlgorithm, _signaturePadding);
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

        private sealed class RsaObjectPoolPolicy : PooledObjectFactory<RSA>
        {
            private readonly RSAParameters _parameters;

            public RsaObjectPoolPolicy(RSAParameters parameters)
            {
                _parameters = parameters;
            }

            public override RSA Create()
            {
#if SUPPORT_SPAN_CRYPTO
                return RSA.Create(_parameters);
#else
                var rsa = new RSACng();
                rsa.ImportParameters(_parameters);
                return rsa;
#endif
            }
        }
    }
}