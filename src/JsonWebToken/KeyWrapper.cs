// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;

namespace JsonWebToken
{
    /// <summary>
    /// Provides key wrapping and key unwrapping services.
    /// </summary>
    public abstract class KeyWrapper : IDisposable
    {
        /// <summary>
        /// Gets the <see cref="Jwk"/> that is being used.
        /// </summary>
        public Jwk Key { get; }

        /// <summary>
        /// Gets the <see cref="KeyManagementAlgorithm"/> that is being used.
        /// </summary>
        public KeyManagementAlgorithm Algorithm { get; }

        /// <summary>
        /// Gets the <see cref="EncryptionAlgorithm"/> that is being used.
        /// </summary>
        public EncryptionAlgorithm EncryptionAlgorithm { get; }

        /// <summary>
        /// Creates a <see cref="KeyWrapper"/>.
        /// </summary>
        /// <param name="key">the key used for key wrapping.</param>
        /// <param name="encryptionAlgorithm">The encryption algorithm.</param>
        /// <param name="contentEncryptionAlgorithm">The content encryption algorithm.</param>
        public static KeyWrapper Create(Jwk key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm contentEncryptionAlgorithm)
        {
            if (key is null)
            {
                return null;
            }

            return key.CreateKeyWrapper(encryptionAlgorithm, contentEncryptionAlgorithm);
        }

        /// <summary>
        /// Initializes a new instances of <see cref="KeyWrapper"/>.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="encryptionAlgorithm"></param>
        /// <param name="algorithm"></param>
        protected KeyWrapper(Jwk key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
        {
            if (key is null)
            {
                Errors.ThrowArgumentNullException(ExceptionArgument.key);
            }

            if (!key.IsSupported(algorithm))
            {
                Errors.ThrowNotSupportedAlgorithmForKeyWrap(algorithm);
            }

            if (algorithm == null)
            {
                Errors.ThrowArgumentNullException(ExceptionArgument.algorithm);
            }

            if (encryptionAlgorithm == null)
            {
                Errors.ThrowArgumentNullException(ExceptionArgument.encryptionAlgorithm);
            }

            Algorithm = algorithm;
            EncryptionAlgorithm = encryptionAlgorithm;
            Key = key;
        }

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

        /// <summary>
        /// Unwrap a key.
        /// </summary>
        /// <param name="keyBytes">key to unwrap.</param>
        /// <param name="destination"></param>
        /// <param name="header"></param>
        /// <param name="bytesWritten"></param>
        /// <returns>Unwrapped key.</returns>
        public abstract bool TryUnwrapKey(ReadOnlySpan<byte> keyBytes, Span<byte> destination, JwtHeader header, out int bytesWritten);

        /// <summary>
        /// Wrap a key.
        /// </summary>
        /// <param name="staticKey">The key to be wrapped. If <c>null</c>, the key will be ephemeral and generated within this method.</param>
        /// <param name="header">The key-values representing the JWT header.</param>
        /// <param name="destination">The destination span.</param>
        /// <param name="contentEncryptionKey">The generated content encryption key.</param>
        /// <param name="bytesWritten">The count of bytes written.</param>
        /// <returns>True .</returns>
        public abstract bool TryWrapKey(Jwk staticKey, JwtObject header, Span<byte> destination, out Jwk contentEncryptionKey, out int bytesWritten);

        /// <summary>
        /// Gets the size of the unwrapped key.
        /// </summary>
        public abstract int GetKeyUnwrapSize(int wrappedKeySize);

        /// <summary>
        /// Gets the size of the wrapped key.
        /// </summary>
        public abstract int GetKeyWrapSize();
    }
}
