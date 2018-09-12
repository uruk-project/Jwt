﻿using JsonWebToken.ObjectPooling;
using System;
using System.Security.Cryptography;

namespace JsonWebToken
{
    public sealed class EcdsaSigner : Signer
    {
        private readonly ObjectPool<ECDsa> _hashAlgorithmPool;
        private readonly int _hashSize;
        private readonly HashAlgorithmName _hashAlgorithm;
        private readonly ECDsa _ecdsa;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="EcdsaSigner"/> class used to create and verify signatures.
        /// </summary>
        /// <param name="key">The <see cref="JsonWebKey"/> that will be used for signature operations.</param>
        /// <param name="algorithm">The signature algorithm to apply.</param>
        /// <param name="willCreateSignatures">Whether is required to create signatures then set this to true.</param>
        public EcdsaSigner(EccJwk key, SignatureAlgorithm algorithm, bool willCreateSignatures)
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

            _ecdsa = ResolveAlgorithm(key, algorithm, willCreateSignatures);
            _hashAlgorithmPool = new ObjectPool<ECDsa>(new ECDsaObjectPoolPolicy(key, algorithm, willCreateSignatures));
        }

        public override int HashSizeInBytes => _hashSize;

        /// <summary>
        /// Produces a signature over the 'input' using the <see cref="ASymmetricJwk"/> and algorithm passed to <see cref="AsymmetricSignatureProvider( JsonWebKey, string, bool )"/>.
        /// </summary>
        /// <param name="input">The bytes to be signed.</param>
        /// <returns>A signature over the input.</returns>
        public override bool TrySign(ReadOnlySpan<byte> input, Span<byte> destination, out int bytesWritten)
        {
            if (input.IsEmpty)
            {
                throw new ArgumentNullException(nameof(input));
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

        /// <summary>
        /// Verifies that a signature over the' input' matches the signature.
        /// </summary>
        /// <param name="input">The bytes to generate the signature over.</param>
        /// <param name="signature">The value to verify against.</param>
        /// <returns>true if signature matches, false otherwise.</returns>
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

#if NETCOREAPP2_1
            return _ecdsa.VerifyData(input, signature, _hashAlgorithm);
#else
            return _ecdsa.VerifyData(input.ToArray(), signature.ToArray(), _hashAlgorithm);
#endif
        }

        private static ECDsa ResolveAlgorithm(EccJwk key, SignatureAlgorithm algorithm, bool usePrivateKey)
        {
            return key.CreateECDsa(algorithm, usePrivateKey);
        }

        /// <summary>
        /// Calls <see cref="ECDsa.Dispose()"/> to release this managed resources.
        /// </summary>
        /// <param name="disposing">true, if called from Dispose(), false, if invoked inside a finalizer.</param>
        protected override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                _disposed = true;

                if (disposing)
                {
                    _ecdsa?.Dispose();
                    _hashAlgorithmPool.Dispose();
                }
            }
        }

        private sealed class ECDsaObjectPoolPolicy : PooledObjectPolicy<ECDsa>
        {
            private readonly EccJwk _key;
            private readonly SignatureAlgorithm _algorithm;
            private readonly bool _usePrivateKey;

            public ECDsaObjectPoolPolicy(EccJwk key, SignatureAlgorithm algorithm, bool usePrivateKey)
            {
                _key = key;
                _algorithm = algorithm;
                _usePrivateKey = usePrivateKey;
            }

            public override ECDsa Create()
            {
                return _key.CreateECDsa(_algorithm, _usePrivateKey);
            }

            public override bool Return(ECDsa obj)
            {
                return true;
            }
        }
    }
}