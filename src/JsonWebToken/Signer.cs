// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;

namespace JsonWebToken
{
    /// <summary>
    /// Provides signature services, signing and verifying.
    /// </summary>
    public abstract class Signer : IDisposable
    {
        /// <summary>
        /// Defines a <see cref="Signer"/> that do nothing.
        /// </summary>
        public static readonly Signer None = new EmptySigner();

        /// <summary>
        /// Initializes a new instance of the <see cref="Signer"/> class used to create and verify signatures.
        /// </summary>
        /// <param name="algorithm">The signature algorithm to apply.</param>
        protected Signer(SignatureAlgorithm algorithm)
        {
            if (algorithm is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.algorithm);
            }

            Algorithm = algorithm;
        }

        /// <summary>
        /// Gets the signature algorithm.
        /// </summary>
        public SignatureAlgorithm Algorithm { get; }

        /// <summary>
        /// Gets the hash size in bytes of the key.
        /// </summary>
        public abstract int HashSizeInBytes { get; }

        /// <summary>
        /// Gets the base64-URL hash size in bits of the key.
        /// </summary>
        public abstract int Base64HashSizeInBytes { get; }

        /// <summary>
        /// This must be overridden to produce a signature over the 'input'.
        /// </summary>
        /// <param name="input">bytes to sign.</param>
        /// <param name="destination"></param>
        /// <param name="bytesWritten"></param>
        /// <returns>signed bytes</returns>
        public abstract bool TrySign(ReadOnlySpan<byte> input, Span<byte> destination, out int bytesWritten);

        /// <summary>
        /// Verify a signature created over the 'input'.
        /// </summary>
        /// <param name="input">bytes to verify.</param>
        /// <param name="signature">signature to compare against.</param>
        /// <returns>true if the computed signature matches the signature parameter, false otherwise.</returns>
        public abstract bool Verify(ReadOnlySpan<byte> input, ReadOnlySpan<byte> signature);
     
        /// <summary>
        /// Verify the firs thalf signature created over the 'input'.
        /// </summary>
        /// <param name="input">bytes to verify.</param>
        /// <param name="signature">signature to compare against.</param>
        /// <returns>true if the computed signature matches the signature parameter, false otherwise.</returns>
        public abstract bool VerifyHalf(ReadOnlySpan<byte> input, ReadOnlySpan<byte> signature);

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

        private sealed class EmptySigner : Signer
        {
            public EmptySigner()
                : base(SignatureAlgorithm.None)
            {
            }

            public override int HashSizeInBytes => 0;

            public override int Base64HashSizeInBytes => 0;

            public override bool TrySign(ReadOnlySpan<byte> input, Span<byte> destination, out int bytesWritten)
            {
                bytesWritten = 0;
                return true;
            }

            public override bool Verify(ReadOnlySpan<byte> input, ReadOnlySpan<byte> signature)
            {
                return true;
            }

            public override bool VerifyHalf(ReadOnlySpan<byte> input, ReadOnlySpan<byte> signature)
            {
                return true;
            }

            protected override void Dispose(bool disposing)
            {
            }
        }
    }
}
