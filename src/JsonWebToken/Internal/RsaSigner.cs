// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using System;
using System.Security.Cryptography;

namespace JsonWebToken
{
    internal sealed class RsaSigner : Signer
    {
        private readonly ObjectPool<RSA> _rsaPool;
        private readonly HashAlgorithmName _hashAlgorithm;
        private readonly int _hashSizeInBytes;
        private readonly RSASignaturePadding _signaturePadding;
        private readonly int _base64HashSizeInBytes;
        private readonly bool _canOnlyVerify;
        private bool _disposed;

        public RsaSigner(RsaJwk key, SignatureAlgorithm algorithm)
            : base(key, algorithm)
        {
            if (key is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.key);
            }

            if (!key.IsSupported(algorithm))
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
            switch (algorithm.Id)
            {
                case Algorithms.RsaSha256:
                case Algorithms.RsaSha384:
                case Algorithms.RsaSha512:
                    _signaturePadding = RSASignaturePadding.Pkcs1;
                    break;

                case Algorithms.RsaSsaPssSha256:
                case Algorithms.RsaSsaPssSha384:
                case Algorithms.RsaSsaPssSha512:
                    _signaturePadding = RSASignaturePadding.Pss;
                    break;

                default:
                    ThrowHelper.ThrowNotSupportedException_Algorithm(algorithm.Name);
                    _signaturePadding = RSASignaturePadding.Pkcs1;
                    break;
            }

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
#if !NETSTANDARD2_0 && !NET461
                return rsa.TrySignData(data, destination, _hashAlgorithm, _signaturePadding, out bytesWritten);
#else
                var result = rsa.SignData(data.ToArray(), _hashAlgorithm, _signaturePadding);
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
#if !NETSTANDARD2_0 && !NET461
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
#if NETSTANDARD2_0 || NET461
                var rsa = new RSACng();
                rsa.ImportParameters(_parameters);
                return rsa;
#else
                return RSA.Create(_parameters);
#endif
            }
        }
    }
}