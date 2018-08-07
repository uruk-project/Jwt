#if NETCOREAPP2_1
using JsonWebToken.ObjectPooling;
using System;
using System.Security.Cryptography;

namespace JsonWebToken
{
    public class ECSignatureProvider : SignatureProvider
    {
        private ECDsa _ecdsa;
        private readonly ObjectPool<ECDsa> _hashAlgorithmPool;
        private int _hashSize;
        private HashAlgorithmName _hashAlgorithm;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="ECSignatureProvider"/> class used to create and verify signatures.
        /// </summary>
        /// <param name="key">The <see cref="JsonWebKey"/> that will be used for signature operations.</param>
        /// <param name="algorithm">The signature algorithm to apply.</param>
        /// <param name="willCreateSignatures">Whether is required to create signatures then set this to true.</param>
        public ECSignatureProvider(ECJwk key, string algorithm, bool willCreateSignatures)
            : base(key, algorithm)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (willCreateSignatures && !key.HasPrivateKey)
            {
                throw new InvalidOperationException(ErrorMessages.FormatInvariant(ErrorMessages.MissingPrivateKey, key.Kid));
            }

            if (key.KeySizeInBits < 256)
            {
                throw new ArgumentOutOfRangeException(nameof(key.KeySizeInBits), ErrorMessages.FormatInvariant(ErrorMessages.SigningKeyTooSmall, key.Kid, 256, key.KeySizeInBits));
            }

            switch (algorithm)
            {
                case SignatureAlgorithms.EcdsaSha256:
                    _hashAlgorithm = HashAlgorithmName.SHA256;
                    break;

                case SignatureAlgorithms.EcdsaSha384:
                    _hashAlgorithm = HashAlgorithmName.SHA256;
                    break;

                case SignatureAlgorithms.EcdsaSha512:
                    _hashAlgorithm = HashAlgorithmName.SHA384;
                    break;

                default:
                    throw new ArgumentOutOfRangeException(nameof(algorithm), ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedAlgorithm, algorithm));
            }

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
                    throw new ArgumentOutOfRangeException(nameof(algorithm), ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedCurve, key.Crv));
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
            if (input == null || input.Length == 0)
            {
                throw new ArgumentNullException(nameof(input));
            }

            if (_ecdsa != null)
            {
#if NETCOREAPP2_1
                return _ecdsa.TrySignData(input, destination, _hashAlgorithm, out bytesWritten);
#else
                var result = _ecdsa.SignData(input.ToArray(), _hashAlgorithm);
                bytesWritten = result.Length;
                result.CopyTo(destination);
#endif
            }

            throw new InvalidOperationException(ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedUnwrap, _hashAlgorithm));
        }

        /// <summary>
        /// Verifies that a signature over the' input' matches the signature.
        /// </summary>
        /// <param name="input">The bytes to generate the signature over.</param>
        /// <param name="signature">The value to verify against.</param>
        /// <returns>true if signature matches, false otherwise.</returns>
        public override bool Verify(ReadOnlySpan<byte> input, ReadOnlySpan<byte> signature)
        {
            if (input == null || input.Length == 0)
            {
                throw new ArgumentNullException(nameof(input));
            }

            if (signature == null || signature.Length == 0)
            {
                throw new ArgumentNullException(nameof(signature));
            }

            if (_ecdsa == null)
            {
                throw new InvalidOperationException(ErrorMessages.NotSupportedUnwrap);
            }

#if NETCOREAPP2_1
            return _ecdsa.VerifyData(input, signature, _hashAlgorithm);
#else
            return _ecdsa.VerifyData(input.ToArray(), signature.ToArray(), _hashAlgorithm);
#endif
        }

        private static ECDsa ResolveAlgorithm(ECJwk key, string algorithm, bool usePrivateKey)
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
                    if (_ecdsa != null)
                    {
                        _ecdsa.Dispose();
                    }
                }
            }
        }

        private class ECDsaObjectPoolPolicy : PooledObjectPolicy<ECDsa>
        {
            private readonly ECJwk _key;
            private readonly string _algorithm;
            private readonly bool _usePrivateKey;

            public ECDsaObjectPoolPolicy(ECJwk key, string algorithm, bool usePrivateKey)
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
#endif