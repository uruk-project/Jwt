// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;

namespace JsonWebToken
{
    /// <summary>
    /// Provides signature services, signing and verifying.
    /// </summary>
    public abstract class Signer : IDisposable
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Signer"/> class used to create and verify signatures.
        /// </summary>
        /// <param name="key">The <see cref="Jwk"/> that will be used for signature operations.</param>
        /// <param name="algorithm">The signature algorithm to apply.</param>
        protected Signer(Jwk key, SignatureAlgorithm algorithm)
        {
            if (key == null)
            {
                Errors.ThrowArgumentNullException(ExceptionArgument.key);
            }

            Key = key;
            Algorithm = algorithm;
        }

        /// <summary>
        /// Gets the <see cref="Jwk"/>.
        /// </summary>
        public Jwk Key { get; }

        /// <summary>
        /// Gets the signature algorithm.
        /// </summary>
        public SignatureAlgorithm Algorithm { get; }

        /// <summary>
        /// Gets the hash size in bits of the key.
        /// </summary>
        public abstract int HashSizeInBytes { get; }

        /// <summary>
        /// This must be overridden to produce a signature over the 'input'.
        /// </summary>
        /// <param name="input">bytes to sign.</param>
        /// <param name="destination"></param>
        /// <param name="bytesWritten"></param>
        /// <returns>signed bytes</returns>
        public abstract bool TrySign(ReadOnlySpan<byte> input, Span<byte> destination, out int bytesWritten);

        /// <summary>
        /// This must be overridden to verify a signature created over the 'input'.
        /// </summary>
        /// <param name="input">bytes to verify.</param>
        /// <param name="signature">signature to compare against.</param>
        /// <returns>true if the computed signature matches the signature parameter, false otherwise.</returns>
        public abstract bool Verify(ReadOnlySpan<byte> input, ReadOnlySpan<byte> signature);
    
        /// <summary>
        /// Calls <see cref="Dispose(bool)"/> and <see cref="GC.SuppressFinalize"/>
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Can be over written in descendants to dispose of internal components.
        /// </summary>
        /// <param name="disposing">true, if called from Dispose(), false, if invoked inside a finalizer</param>     
        protected abstract void Dispose(bool disposing);
    }
}
