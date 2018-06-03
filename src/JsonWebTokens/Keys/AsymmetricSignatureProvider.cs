using System;
using System.Collections.Generic;

namespace JsonWebTokens
{
    /// <summary>
    /// Provides signing and verifying operations when working with an <see cref="AsymmetricJwk"/>
    /// </summary>
    public abstract class AsymmetricSignatureProvider<TKey> : SignatureProvider where TKey : AsymmetricJwk
    {
        public abstract IReadOnlyDictionary<string, int> MinimumKeySizeInBitsForSigning { get; }

        public abstract IReadOnlyDictionary<string, int> MinimumKeySizeInBitsForVerifying { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="AsymmetricSignatureProvider"/> class used to create and verify signatures.
        /// </summary>
        /// <param name="key">The <see cref="TKey"/> that will be used for signature operations.</param>
        /// <param name="algorithm">The signature algorithm to apply.</param>
        /// <param name="willCreateSignatures">Whether this <see cref="AsymmetricSignatureProvider"/> is required to create signatures then set this to true.</param>
        /// <para>
        /// Creating signatures requires that the <see cref="TKey"/> has access to a private key.
        /// Verifying signatures (the default), does not require access to the private key.
        /// </para>
        public AsymmetricSignatureProvider(TKey key, string algorithm, bool willCreateSignatures)
            : base(key, algorithm)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (willCreateSignatures && FoundPrivateKey(key) == PrivateKeyStatus.DoesNotExist)
            {
                throw new InvalidOperationException(ErrorMessages.FormatInvariant(ErrorMessages.MissingPrivateKey, key.Kid));
            }

            if (!key.IsSupportedAlgorithm(algorithm))
            {
                throw new NotSupportedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedSignatureAlgorithm, (algorithm ?? "null"), key));
            }

            ValidateAsymmetricJwkSize(key, algorithm, willCreateSignatures);
            ResolveAsymmetricAlgorithm(key, algorithm, willCreateSignatures);
        }

        protected abstract void ResolveAsymmetricAlgorithm(TKey key, string algorithm, bool willCreateSignatures);

        private PrivateKeyStatus FoundPrivateKey(AsymmetricJwk key)
        {
            return key.HasPrivateKey ? PrivateKeyStatus.Exists : PrivateKeyStatus.DoesNotExist;
        }

        private void ValidateAsymmetricJwkSize(TKey key, string algorithm, bool willCreateSignatures)
        {
            if (willCreateSignatures && MinimumKeySizeInBitsForSigning.ContainsKey(algorithm) && key.KeySize < MinimumKeySizeInBitsForSigning[algorithm])
            {
                throw new ArgumentOutOfRangeException(nameof(key.KeySize), ErrorMessages.FormatInvariant(ErrorMessages.SigningKeyTooSmall, key.Kid, MinimumKeySizeInBitsForSigning[algorithm], key.KeySize));
            }

            if (MinimumKeySizeInBitsForVerifying.ContainsKey(algorithm) && key.KeySize < MinimumKeySizeInBitsForVerifying[algorithm])
            {
                throw new ArgumentOutOfRangeException(nameof(key.KeySize), ErrorMessages.FormatInvariant(ErrorMessages.VerifyKeyTooSmall, key.Kid, MinimumKeySizeInBitsForVerifying[algorithm], key.KeySize));
            }
        }
    }
}


