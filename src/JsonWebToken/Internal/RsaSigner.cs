// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using System;
using System.Security.Cryptography;

namespace JsonWebToken
{
    internal sealed class RsaSigner : Signer
    {
        private readonly ObjectPool<RSA> _hashAlgorithmPool;
        private readonly HashAlgorithmName _hashAlgorithm;
        private readonly int _hashSizeInBytes;
        private readonly RSASignaturePadding _signaturePadding;
        private readonly int _base64HashSizeInBytes;
        private bool _disposed;

        public RsaSigner(RsaJwk key, SignatureAlgorithm algorithm, bool willCreateSignatures)
            : base(key, algorithm)
        {
            if (key is null)
            {
                Errors.ThrowArgumentNullException(ExceptionArgument.key);
            }

            if (willCreateSignatures && !key.HasPrivateKey)
            {
                Errors.ThrowMissingPrivateKey(key);
            }

            if (!key.IsSupported(algorithm))
            {
                Errors.ThrowNotSupportedSignatureAlgorithm(algorithm, key);
            }

            var minKeySize = willCreateSignatures ? 2048 : 1024;
            if (key.KeySizeInBits < minKeySize)
            {
                Errors.ThrowSigningKeyTooSmall(key, minKeySize);
            }

            _hashAlgorithm = algorithm.HashAlgorithm;
            switch (algorithm.Name)
            {
                case "RS256":
                case "RS384":
                case "RS512":
                    _signaturePadding = RSASignaturePadding.Pkcs1;
                    break;

                case "PS256":
                case "PS384":
                case "PS512":
                    _signaturePadding = RSASignaturePadding.Pss;
                    break;

                default:
                    Errors.ThrowNotSupportedAlgorithm(algorithm);
                    break;
            }

            _hashSizeInBytes = key.KeySizeInBits >> 3;
            _base64HashSizeInBytes = Base64Url.GetArraySizeRequiredToEncode(_hashSizeInBytes);
            _hashAlgorithmPool = new ObjectPool<RSA>(new RsaObjectPoolPolicy(key.ExportParameters()));
        }

        public override int HashSizeInBytes => _hashSizeInBytes;

        public override int Base64HashSizeInBytes => _base64HashSizeInBytes;

        public override bool TrySign(ReadOnlySpan<byte> data, Span<byte> destination, out int bytesWritten)
        {
            if (data.IsEmpty)
            {
                Errors.ThrowArgumentNullException(ExceptionArgument.data);
            }

            if (_disposed)
            {
                Errors.ThrowObjectDisposed(GetType());
            }

            var rsa = _hashAlgorithmPool.Get();
            try
            {
#if !NETSTANDARD2_0
                return rsa.TrySignData(data, destination, _hashAlgorithm, _signaturePadding, out bytesWritten);
#else
                try
                {
                    var result = rsa.SignData(data.ToArray(), _hashAlgorithm, _signaturePadding);
                    bytesWritten = result.Length;
                    result.CopyTo(destination);
                    return true;
                }
                catch
                {
                    return Errors.TryWriteError(out bytesWritten);
                }
#endif
            }
            finally
            {
                _hashAlgorithmPool.Return(rsa);
            }
        }

        public override bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
        {
            if (data.IsEmpty)
            {
                Errors.ThrowArgumentNullException(ExceptionArgument.data);
            }

            if (signature.IsEmpty)
            {
                Errors.ThrowArgumentNullException(ExceptionArgument.signature);
            }

            if (_disposed)
            {
                Errors.ThrowObjectDisposed(GetType());
            }

            var rsa = _hashAlgorithmPool.Get();
            try
            {
#if !NETSTANDARD2_0
                return rsa.VerifyData(data, signature, _hashAlgorithm, _signaturePadding);
#else
                return rsa.VerifyData(data.ToArray(), signature.ToArray(), _hashAlgorithm, _signaturePadding);
#endif
            }
            finally
            {
                _hashAlgorithmPool.Return(rsa);
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    _hashAlgorithmPool.Dispose();
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
#if !NETSTANDARD2_0
                return RSA.Create(_parameters);
#else
                var rsa = RSA.Create();
                rsa.ImportParameters(_parameters);
                return rsa;
#endif
            }
        }
    }
}