using JsonWebToken.Internal;
using System;
using System.Security.Cryptography;

namespace JsonWebToken
{
    public sealed class RsaSigner : Signer
    {
        private readonly ObjectPool<RSA> _hashAlgorithmPool;
        private readonly HashAlgorithmName _hashAlgorithm;
        private readonly int _hashSizeInBytes;
        private readonly RSASignaturePadding _signaturePadding;

        private bool _disposed;

        public RsaSigner(RsaJwk key, SignatureAlgorithm algorithm, bool willCreateSignatures)
            : base(key, algorithm)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
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
            _hashAlgorithmPool = new ObjectPool<RSA>(new RsaObjectPoolPolicy(key.ExportParameters()));
        }

        public override int HashSizeInBytes => _hashSizeInBytes;

        public override bool TrySign(ReadOnlySpan<byte> input, Span<byte> destination, out int bytesWritten)
        {
            if (input.IsEmpty)
            {
                throw new ArgumentNullException(nameof(input));
            }

            if (_disposed)
            {
                Errors.ThrowObjectDisposed(GetType());
            }

            var rsa = _hashAlgorithmPool.Get();
            try
            {
#if NETCOREAPP2_1
                return rsa.TrySignData(input, destination, _hashAlgorithm, _signaturePadding, out bytesWritten);
#else
                try
                {
                    var result = rsa.SignData(input.ToArray(), _hashAlgorithm, _signaturePadding);
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

        public override bool Verify(ReadOnlySpan<byte> input, ReadOnlySpan<byte> signature)
        {
            if (input.IsEmpty)
            {
                throw new ArgumentNullException(nameof(input));
            }

            if (signature.IsEmpty)
            {
                throw new ArgumentNullException(nameof(signature));
            }

            if (_disposed)
            {
                Errors.ThrowObjectDisposed(GetType());
            }

            var rsa = _hashAlgorithmPool.Get();
            try
            {
#if NETCOREAPP2_1
                return rsa.VerifyData(input, signature, _hashAlgorithm, _signaturePadding);
#else
                return rsa.VerifyData(input.ToArray(), signature.ToArray(), _hashAlgorithm, _signaturePadding);
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

        private sealed class RsaObjectPoolPolicy : PooledObjectPolicy<RSA>
        {
            private readonly RSAParameters _parameters;

            public RsaObjectPoolPolicy(RSAParameters parameters)
            {
                _parameters = parameters;
            }

            public override RSA Create()
            {
#if NETCOREAPP2_1
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