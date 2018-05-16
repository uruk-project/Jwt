using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace JsonWebToken
{
    public class RsaSignatureProvider : AsymmetricSignatureProvider<RsaJwk>
    {
        private HashAlgorithmName _hashAlgorithm;
        private RSA _rsa;

        private bool _disposed;

        /// <summary>
        /// Mapping from algorithm to minimum <see cref="ASymmetricJwk"/>.KeySize when creating signatures.
        /// </summary>
        private static readonly IReadOnlyDictionary<string, int> DefaultMinimumKeySizeInBitsForSigning = new Dictionary<string, int>()
        {
            { SecurityAlgorithms.RsaSha256, 2048 },
            { SecurityAlgorithms.RsaSha384, 2048 },
            { SecurityAlgorithms.RsaSha512, 2048 },
        };

        /// <summary>
        /// Mapping from algorithm to minimum <see cref="ASymmetricJwk"/>.KeySize when verifying signatures.
        /// </summary>
        private static readonly IReadOnlyDictionary<string, int> DefaultMinimumKeySizeInBitsForVerifying = new Dictionary<string, int>()
        {
            { SecurityAlgorithms.RsaSha256, 1024 },
            { SecurityAlgorithms.RsaSha384, 1024 },
            { SecurityAlgorithms.RsaSha512, 1024 },
        };

        public override IReadOnlyDictionary<string, int> MinimumKeySizeInBitsForSigning => DefaultMinimumKeySizeInBitsForSigning;

        public override IReadOnlyDictionary<string, int> MinimumKeySizeInBitsForVerifying => DefaultMinimumKeySizeInBitsForVerifying;

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
            : base(key, algorithm, willCreateSignatures)
        {
        }

        /// <summary>
        /// Returns the <see cref="HashAlgorithmName"/> instance.
        /// </summary>
        /// <param name="algorithm">The hash algorithm to use to create the hash value.</param>
        private HashAlgorithmName GetHashAlgorithmName(string algorithm)
        {
            if (string.IsNullOrWhiteSpace(algorithm))
            {
                throw new ArgumentNullException("algorithm");
            }

            switch (algorithm)
            {
                case SecurityAlgorithms.RsaSha256:
                    return HashAlgorithmName.SHA256;

                case SecurityAlgorithms.RsaSha384:
                    return HashAlgorithmName.SHA384;

                case SecurityAlgorithms.RsaSha512:
                    return HashAlgorithmName.SHA512;
            }

            throw new ArgumentOutOfRangeException(nameof(algorithm), ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedAlgorithm, algorithm));
        }

        protected override void ResolveAsymmetricAlgorithm(RsaJwk key, string algorithm, bool willCreateSignatures)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (string.IsNullOrWhiteSpace(algorithm))
            {
                throw new ArgumentNullException(nameof(algorithm));
            }

            _hashAlgorithm = GetHashAlgorithmName(algorithm);
            var rsa = ResolveRsaAlgorithm(key, algorithm, willCreateSignatures);
            if (rsa != null)
            {
                _rsa = rsa;
                return;
            }

            throw new NotSupportedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedSignatureAlgorithm, algorithm, key));
        }

        /// <summary>
        /// Produces a signature over the 'input' using the <see cref="ASymmetricJwk"/> and algorithm passed to <see cref="AsymmetricSignatureProvider( JsonWebKey, string, bool )"/>.
        /// </summary>
        /// <param name="input">The bytes to be signed.</param>
        /// <returns>A signature over the input.</returns>
        public override byte[] Sign(byte[] input)
        {
            if (input == null || input.Length == 0)
            {
                throw new ArgumentNullException(nameof(input));
            }

            if (_disposed)
            {
                throw new ObjectDisposedException(GetType().ToString());
            }

            if (_rsa != null)
            {
                //_rsa.TrySignData(input, _hashAlgorithm)
                return _rsa.SignData(input, _hashAlgorithm, RSASignaturePadding.Pkcs1);
            }

            throw new InvalidOperationException(ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedUnwrap, _hashAlgorithm));
        }

        /// <summary>
        /// Verifies that a signature over the' input' matches the signature.
        /// </summary>
        /// <param name="input">The bytes to generate the signature over.</param>
        /// <param name="signature">The value to verify against.</param>
        /// <returns>true if signature matches, false otherwise.</returns>
        public override bool Verify(byte[] input, byte[] signature)
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

            if (_rsa != null)
            {
                return _rsa.VerifyData(input, signature, _hashAlgorithm, RSASignaturePadding.Pkcs1);
            }

            throw new InvalidOperationException(ErrorMessages.NotSupportedUnwrap);
        }

        /// <summary>
        /// Calls <see cref="HashAlgorithm.Dispose()"/> to release this managed resources.
        /// </summary>
        /// <param name="disposing">true, if called from Dispose(), false, if invoked inside a finalizer.</param>
        protected override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                _disposed = true;

                if (disposing)
                {
                    if (_rsa != null)
                    {
                        _rsa.Dispose();
                    }
                }
            }
        }

        private static RSA ResolveRsaAlgorithm(RsaJwk key, string algorithm, bool requirePrivateKey)
        {
            if (key == null)
            {
                return null;
            }

            RSAParameters parameters = key.CreateRsaParameters();
            var rsa = RSA.Create();
            if (rsa != null)
            {
                rsa.ImportParameters(parameters);
            }
            return rsa;
        }
    }
}