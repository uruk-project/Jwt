// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Diagnostics;

namespace JsonWebToken.Cryptography
{
    /// <summary>Provides key unwrapping services.</summary>
    public abstract class KeyUnwrapper : IDisposable
    {
        /// <summary>Gets the <see cref="KeyManagementAlgorithm"/> that is being used.</summary>
        public KeyManagementAlgorithm Algorithm { get; }

        /// <summary>Gets the <see cref="EncryptionAlgorithm"/> that is being used.</summary>
        public EncryptionAlgorithm EncryptionAlgorithm { get; }

        /// <summary>Initializes a new instance of the <see cref="KeyUnwrapper"/> class.</summary>
        protected KeyUnwrapper(EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
        {
            Debug.Assert(algorithm != null);
            Debug.Assert(encryptionAlgorithm != null);

            Algorithm = algorithm;
            EncryptionAlgorithm = encryptionAlgorithm;
        }

        /// <summary>Calls <see cref="Dispose(bool)"/> and <see cref="GC.SuppressFinalize"/></summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>Can be over written in descendants to dispose of internal components.</summary>
        /// <param name="disposing">true, if called from Dispose(), false, if invoked inside a finalizer</param>     
        protected abstract void Dispose(bool disposing);

        /// <summary>Unwrap a key.</summary>
        /// <param name="keyBytes">key to unwrap.</param>
        /// <param name="destination"></param>
        /// <param name="header"></param>
        /// <param name="bytesWritten"></param>
        /// <returns>Unwrapped key.</returns>
        public abstract bool TryUnwrapKey(ReadOnlySpan<byte> keyBytes, Span<byte> destination, JwtHeaderDocument header, out int bytesWritten);

        /// <summary>Gets the size of the unwrapped key.</summary>
        public abstract int GetKeyUnwrapSize(int wrappedKeySize);
    }
}
