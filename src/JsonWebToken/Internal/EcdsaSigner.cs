using System;
using System.Security.Cryptography;

namespace JsonWebToken.Internal
{
    public sealed class EcdsaSigner : Signer
    {
        private readonly ObjectPool<ECDsa> _hashAlgorithmPool;
        private readonly int _hashSize;
        private readonly HashAlgorithmName _hashAlgorithm;
        private readonly ECDsa _ecdsa;
        private bool _disposed;

        public EcdsaSigner(ECJwk key, SignatureAlgorithm algorithm, bool willCreateSignatures)
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

            if (key.KeySizeInBits < 256)
            {
                Errors.ThrowSigningKeyTooSmall(key, 256);
            }

            _hashAlgorithm = algorithm.HashAlgorithm;

            switch (key.Crv)
            {
                case EllipticalCurves.P256:
                    _hashSize = 64;
                    break;
                case EllipticalCurves.P384:
                    _hashSize = 96;
                    break;
                case EllipticalCurves.P521:
                    _hashSize = 132;
                    break;
                default:
                    Errors.ThrowNotSupportedCurve(key.Crv);
                    break;
            }

            _ecdsa = key.CreateECDsa(algorithm, willCreateSignatures);
            _hashAlgorithmPool = new ObjectPool<ECDsa>(new ECDsaObjectPoolPolicy(key, algorithm, willCreateSignatures));
        }

        public override int HashSizeInBytes => _hashSize;

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

#if NETCOREAPP2_1
            return _ecdsa.TrySignData(input, destination, _hashAlgorithm, out bytesWritten);
#else
            var result = _ecdsa.SignData(input.ToArray(), _hashAlgorithm);
            bytesWritten = result.Length;
            result.CopyTo(destination);
            return true;
#endif
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

#if NETCOREAPP2_1
            return _ecdsa.VerifyData(input, signature, _hashAlgorithm);
#else
            return _ecdsa.VerifyData(input.ToArray(), signature.ToArray(), _hashAlgorithm);
#endif
        }

        protected override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    _ecdsa?.Dispose();
                    _hashAlgorithmPool.Dispose();
                }

                _disposed = true;
            }
        }

        private sealed class ECDsaObjectPoolPolicy : PooledObjectPolicy<ECDsa>
        {
            private readonly ECJwk _key;
            private readonly SignatureAlgorithm _algorithm;
            private readonly bool _usePrivateKey;

            public ECDsaObjectPoolPolicy(ECJwk key, SignatureAlgorithm algorithm, bool usePrivateKey)
            {
                _key = key;
                _algorithm = algorithm;
                _usePrivateKey = usePrivateKey;
            }

            public override ECDsa Create()
            {
                return _key.CreateECDsa(_algorithm, _usePrivateKey);
            }
        }
    }
}