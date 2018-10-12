using Newtonsoft.Json.Linq;
using System;

namespace JsonWebToken
{
    /// <summary>
    /// Provides Wrap key and Unwrap key services.
    /// </summary>
    public abstract class KeyWrapper : IDisposable
    {
        /// <summary>
        /// Gets the KeyWrap algorithm that is being used.
        /// </summary>
        protected KeyManagementAlgorithm Algorithm;

        protected EncryptionAlgorithm EncryptionAlgorithm;

        /// <summary>
        /// Gets the <see cref="JsonWebKey"/> that is being used.
        /// </summary>
        public JsonWebKey Key { get; protected set; }

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
