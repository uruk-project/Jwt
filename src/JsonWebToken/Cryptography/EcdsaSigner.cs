// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

#if NETCOREAPP ||NETSTANDARD || NET47
using System;
using System.Security.Cryptography;

namespace JsonWebToken.Internal
{
    internal sealed class EcdsaSigner : Signer
    {
        private readonly ObjectPool<ECDsa> _ecdsaPool;
        private readonly int _hashSize;
        private readonly HashAlgorithmName _hashAlgorithm;
        private readonly int _base64HashSize;
        private readonly bool _canOnlyVerify;
        private bool _disposed;

        public EcdsaSigner(ECJwk key, SignatureAlgorithm algorithm)
            : base(algorithm)
        {
            if (key is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.key);
            }

            if (key.KeySizeInBits < 256)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException_SigningKeyTooSmall(key, 256);
            }

            _canOnlyVerify = !key.HasPrivateKey;
            _hashAlgorithm = algorithm.HashAlgorithm;
            _hashSize = key.Crv.HashSize;
            _base64HashSize = Base64Url.GetArraySizeRequiredToEncode(_hashSize);

            _ecdsaPool = new ObjectPool<ECDsa>(new ECDsaObjectPoolPolicy(key, algorithm));
        }

        /// <inheritsdoc />
        public override int HashSizeInBytes => _hashSize;

        public override int Base64HashSizeInBytes => _base64HashSize;

        /// <inheritsdoc />
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

            var ecdsa = _ecdsaPool.Get();
#if !NETSTANDARD2_0 && !NET461
            return ecdsa.TrySignData(data, destination, _hashAlgorithm, out bytesWritten);
#else
            var result = ecdsa.SignData(data.ToArray(), _hashAlgorithm);
            bytesWritten = result.Length;
            result.CopyTo(destination);
            return true;
#endif
        }

        /// <inheritsdoc />
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

            var ecdsa = _ecdsaPool.Get();
#if NETSTANDARD2_0 || NET461
            return ecdsa.VerifyData(data.ToArray(), signature.ToArray(), _hashAlgorithm);
#else
            return ecdsa.VerifyData(data, signature, _hashAlgorithm);
#endif
        }

        /// <inheritsdoc />
        protected override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    _ecdsaPool.Dispose();
                }

                _disposed = true;
            }
        }

        private sealed class ECDsaObjectPoolPolicy : PooledObjectFactory<ECDsa>
        {
            private readonly ECJwk _key;
            private readonly SignatureAlgorithm _algorithm;
            private readonly bool _usePrivateKey;

            public ECDsaObjectPoolPolicy(ECJwk key, SignatureAlgorithm algorithm)
            {
                _key = key;
                _algorithm = algorithm;
                _usePrivateKey = key.HasPrivateKey;
            }

            public override ECDsa Create()
            {
                return _key.CreateECDsa(_algorithm, _usePrivateKey);
            }
        }
    }
}
#endif