// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using Newtonsoft.Json.Linq;
using System;

namespace JsonWebToken
{
    /// <summary>
    /// Provides key wrapping and key unwrapping services.
    /// </summary>
    public abstract class KeyWrapper : IDisposable
    {
        /// <summary>
        /// Gets the <see cref="JsonWebKey"/> that is being used.
        /// </summary>
        public JsonWebKey Key { get; }

        /// <summary>
        /// Gets the <see cref="KeyManagementAlgorithm"/> that is being used.
        /// </summary>
        public KeyManagementAlgorithm Algorithm { get; }

        /// <summary>
        /// Gets the <see cref="EncryptionAlgorithm"/> that is being used.
        /// </summary>
        public EncryptionAlgorithm EncryptionAlgorithm { get; }

        protected KeyWrapper(JsonWebKey key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (!key.IsSupported(algorithm))
            {
                Errors.ThrowNotSupportedAlgorithmForKeyWrap(algorithm);
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
        /// <returns>Unwrapped key.</returns>
        public abstract bool TryUnwrapKey(ReadOnlySpan<byte> keyBytes, Span<byte> destination, JwtHeader header, out int bytesWritten);

        /// <summary>
        /// Wrap a key.
        /// </summary>
        /// <param name="staticKey">The key to be wrapped. If <c>null</c>, the key will be ephemeral and generated within this method.</param>
        /// <returns>wrapped key.</returns>
        public abstract bool TryWrapKey(JsonWebKey staticKey, JObject header, Span<byte> destination, out JsonWebKey contentEncryptionKey, out int bytesWritten);

        public abstract int GetKeyUnwrapSize(int inputSize);

        public abstract int GetKeyWrapSize();
    }
}
