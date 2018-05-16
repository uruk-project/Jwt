using System;

namespace JsonWebToken
{
    /// <summary>
    /// Provides Wrap key and Unwrap key services.
    /// </summary>
    public abstract class KeyWrapProvider : IDisposable
    {
        /// <summary>
        /// Gets the KeyWrap algorithm that is being used.
        /// </summary>
        public string Algorithm { get; protected set; }

        /// <summary>
        /// Gets the <see cref="SecurityKey"/> that is being used.
        /// </summary>
        public JsonWebKey Key { get; protected set; }

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
        public abstract byte[] UnwrapKey(byte[] keyBytes);

        /// <summary>
        /// Wrap a key.
        /// </summary>
        /// <param name="keyBytes">the key to be wrapped</param>
        /// <returns>wrapped key.</returns>
        public abstract byte[] WrapKey(byte[] keyBytes);
    }
}
