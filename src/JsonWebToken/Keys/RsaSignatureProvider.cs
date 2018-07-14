using JsonWebToken.ObjectPooling;
using System;
using System.Security.Cryptography;

namespace JsonWebToken
{
    public class RsaSignatureProvider : SignatureProvider
    {
        private readonly ObjectPool<RSA> _hashAlgorithmPool;

        private HashAlgorithmName _hashAlgorithm;
        private int _hashSizeInBytes;
        private RSASignaturePadding _signaturePadding;

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
        public RsaSignatureProvider(RsaJwk key, string algorithm, bool willCreateSignatures)
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

            if (!key.IsSupportedAlgorithm(algorithm))
            {
                throw new NotSupportedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedSignatureAlgorithm, (algorithm ?? "null"), key));
            }

            var minKeySize = willCreateSignatures ? 2048 : 1024;
            if (key.KeySizeInBits < minKeySize)
            {
                throw new ArgumentOutOfRangeException(nameof(key.KeySizeInBits), ErrorMessages.FormatInvariant(ErrorMessages.SigningKeyTooSmall, key.Kid, minKeySize, key.KeySizeInBits));
            }

            switch (algorithm)
            {
                case SignatureAlgorithms.RsaSha256:
                    _hashAlgorithm = HashAlgorithmName.SHA256;
                    _signaturePadding = RSASignaturePadding.Pkcs1;
                    break;

                case SignatureAlgorithms.RsaSsaPssSha256:
                    _hashAlgorithm = HashAlgorithmName.SHA256;
                    _signaturePadding = RSASignaturePadding.Pss;
                    break;

                case SignatureAlgorithms.RsaSha384:
                    _hashAlgorithm = HashAlgorithmName.SHA384;
                    _signaturePadding = RSASignaturePadding.Pkcs1;
                    break;

                case SignatureAlgorithms.RsaSsaPssSha384:
                    _hashAlgorithm = HashAlgorithmName.SHA384;
                    _signaturePadding = RSASignaturePadding.Pss;
                    break;

                case SignatureAlgorithms.RsaSha512:
                    _hashAlgorithm = HashAlgorithmName.SHA512;
                    _signaturePadding = RSASignaturePadding.Pkcs1;
                    break;

                case SignatureAlgorithms.RsaSsaPssSha512:
                    _hashAlgorithm = HashAlgorithmName.SHA512;
                    _signaturePadding = RSASignaturePadding.Pss;
                    break;

                default:
                    throw new ArgumentOutOfRangeException(nameof(algorithm), ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedAlgorithm, algorithm));
            }

            _hashSizeInBytes = key.KeySizeInBits >> 3;
            _hashAlgorithmPool = new ObjectPool<RSA>(new RsaObjectPoolPolicy(key.CreateRsaParameters()));
        }

        public override int HashSizeInBytes => _hashSizeInBytes;

        /// <summary>
        /// Produces a signature over the 'input' using the <see cref="AsymmetricJwk"/> and algorithm passed to <see cref="AsymmetricSignatureProvider( JsonWebKey, string, bool )"/>.
        /// </summary>
        /// <param name="input">The bytes to be signed.</param>
        /// <returns>A signature over the input.</returns>
        public override bool TrySign(ReadOnlySpan<byte> input, Span<byte> destination, out int bytesWritten)
        {
            if (input == null || input.Length == 0)
            {
                throw new ArgumentNullException(nameof(input));
            }

            if (_disposed)
            {
                throw new ObjectDisposedException(GetType().ToString());
            }

            var _rsa = _hashAlgorithmPool.Get();
            try
            {
#if NETCOREAPP2_1
                return _rsa.TrySignData(input, destination, _hashAlgorithm, _signaturePadding, out bytesWritten);
#else
                try
                {
                    var result = _rsa.SignData(input.ToArray(), _hashAlgorithm, _signaturePadding);
                    bytesWritten = result.Length;
                    result.CopyTo(destination);
                    return true;
                }
                catch
                {
                    bytesWritten = 0;
                    return false;
                }
#endif
            }
            finally
            {
                _hashAlgorithmPool.Return(_rsa);
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
            if (input == null || input.Length == 0)
            {
                throw new ArgumentNullException(nameof(input));
            }

            if (signature == null || signature.Length == 0)
            {
                throw new ArgumentNullException(nameof(signature));
            }

            if (_disposed)
            {
                throw new ObjectDisposedException(GetType().ToString());
            }

            var _rsa = _hashAlgorithmPool.Get();
            try
            {
#if NETCOREAPP2_1
                return _rsa.VerifyData(input, signature, _hashAlgorithm, _signaturePadding);
#else
                return _rsa.VerifyData(input.ToArray(), signature.ToArray(), _hashAlgorithm, _signaturePadding);
#endif
            }
            finally
            {
                _hashAlgorithmPool.Return(_rsa);
            }
        }

        private class RsaObjectPoolPolicy : PooledObjectPolicy<RSA>
        {
            private readonly RSAParameters _parameters;

            public RsaObjectPoolPolicy(RSAParameters parameters)
            {
                _parameters = parameters;
            }

            public override RSA Create()
            {
                var rsa = RSA.Create();
                rsa.ImportParameters(_parameters);
                return rsa;
            }

            public override bool Return(RSA obj)
            {
                return true;
            }
        }
    }
}