using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace JsonWebToken
{
    public class RsaSignatureProvider : AsymmetricSignatureProvider<RsaJwk>
    {
        private HashAlgorithmName _hashAlgorithm;
        private int _hashSize;
        private RSASignaturePadding _signaturePadding;
        private RSA _rsa;

        private bool _disposed;

        /// <summary>
        /// Mapping from algorithm to minimum <see cref="ASymmetricJwk"/>.KeySize when creating signatures.
        /// </summary>
        private static readonly IReadOnlyDictionary<string, int> DefaultMinimumKeySizeInBitsForSigning = new Dictionary<string, int>()
        {
            { SignatureAlgorithms.RsaSha256, 2048 },
            { SignatureAlgorithms.RsaSha384, 2048 },
            { SignatureAlgorithms.RsaSha512, 2048 },
        };

        /// <summary>
        /// Mapping from algorithm to minimum <see cref="ASymmetricJwk"/>.KeySize when verifying signatures.
        /// </summary>
        private static readonly IReadOnlyDictionary<string, int> DefaultMinimumKeySizeInBitsForVerifying = new Dictionary<string, int>()
        {
            { SignatureAlgorithms.RsaSha256, 1024 },
            { SignatureAlgorithms.RsaSha384, 1024 },
            { SignatureAlgorithms.RsaSha512, 1024 },
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

        public override int HashSizeInBits => _hashSize;

        /// <summary>
        /// Returns the <see cref="HashAlgorithmName"/> instance.
        /// </summary>
        /// <param name="algorithm">The hash algorithm to use to create the hash value.</param>
        private HashAlgorithmName GetHashAlgorithmName(string algorithm)
        {
            if (string.IsNullOrWhiteSpace(algorithm))
            {
                throw new ArgumentNullException(nameof(algorithm));
            }

            switch (algorithm)
            {
                case SignatureAlgorithms.RsaSha256:
                case SignatureAlgorithms.RsaSsaPssSha256:
                    return HashAlgorithmName.SHA256;

                case SignatureAlgorithms.RsaSha384:
                case SignatureAlgorithms.RsaSsaPssSha384:
                    return HashAlgorithmName.SHA384;

                case SignatureAlgorithms.RsaSha512:
                case SignatureAlgorithms.RsaSsaPssSha512:
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
            _hashSize = GetHashSize(key);
            _signaturePadding = ResolveSignaturePadding(algorithm);
            var rsa = ResolveRsaAlgorithm(key);
            if (rsa != null)
            {
                _rsa = rsa;
                return;
            }

            throw new NotSupportedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedSignatureAlgorithm, algorithm, key.Kid));
        }

        private RSASignaturePadding ResolveSignaturePadding(string algorithm)
        {
            switch (algorithm)
            {
                case SignatureAlgorithms.RsaSha256:
                case SignatureAlgorithms.RsaSha384:
                case SignatureAlgorithms.RsaSha512:
                    return RSASignaturePadding.Pkcs1;

                case SignatureAlgorithms.RsaSsaPssSha384:
                case SignatureAlgorithms.RsaSsaPssSha256:
                case SignatureAlgorithms.RsaSsaPssSha512:
                    return RSASignaturePadding.Pss;
            }

            throw new ArgumentOutOfRangeException(nameof(algorithm), ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedAlgorithm, algorithm));
        }

        private int GetHashSize(RsaJwk key)
        {
            return key.KeySize;
        }

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

            if (_rsa != null)
            {
#if NETCOREAPP2_1
                return _rsa.TrySignData(input, destination, _hashAlgorithm, _signaturePadding, out bytesWritten);
#else
                try
                {
                    var result = _rsa.SignData(input.ToArray(), _hashAlgorithm, _signaturePadding);
                    bytesWritten = result.Length;
                    result.CopyTo(destination);
                }
                catch
                {
                    bytesWritten = 0;
                    return false;
                }
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

            if (_disposed)
            {
                throw new ObjectDisposedException(GetType().ToString());
            }

            if (_rsa != null)
            {
#if NETCOREAPP2_1
                return _rsa.VerifyData(input, signature, _hashAlgorithm, _signaturePadding);
#else
                return _rsa.VerifyData(input.ToArray(), signature.ToArray(), _hashAlgorithm, _signaturePadding);
#endif
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

        private static RSA ResolveRsaAlgorithm(RsaJwk key)
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