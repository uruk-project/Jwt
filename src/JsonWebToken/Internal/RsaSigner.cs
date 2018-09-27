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

        /// <summary>
        /// Initializes a new instance of the <see cref="AsymmetricSignatureProvider"/> class used to create and verify signatures.
        /// </summary>
        /// <param name="key">The <see cref="JsonWebKey"/> that will be used for signature operations.</param>
        /// <param name="algorithm">The signature algorithm to apply.</param>
        /// <param name="willCreateSignatures">Whether this <see cref="AsymmetricSignatureProvider"/> is required to create signatures then set this to true.</param>
        /// <para>
        /// Creating signatures requires that the <see cref="JsonWebKey"/> has access to a private key.
        /// Verifying signatures (the default), does not require access to the private key.
        /// </para>
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

        /// <summary>
        /// Produces a signature over the 'input' using the <see cref="AsymmetricJwk"/> and algorithm passed to <see cref="AsymmetricSignatureProvider( JsonWebKey, string, bool )"/>.
        /// </summary>
        /// <param name="input">The bytes to be signed.</param>
        /// <returns>A signature over the input.</returns>
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

        /// <summary>
        /// Calls <see cref="RSA.Dispose()"/> to release this managed resources.
        /// </summary>
        /// <param name="disposing">true, if called from Dispose(), false, if invoked inside a finalizer.</param>
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