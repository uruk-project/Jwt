// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Runtime.CompilerServices;

namespace JsonWebToken
{
    /// <summary>
    /// Provides key wrapping services.
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
        /// Initializes a new instance of the <see cref="KeyWrapper"/> class.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="encryptionAlgorithm"></param>
        /// <param name="algorithm"></param>
        protected KeyWrapper(Jwk key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
        {
            if (key is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.key);
            }

            if (!key.SupportKeyManagement(algorithm))
            {
                ThrowHelper.ThrowNotSupportedException_AlgorithmForKeyWrap(algorithm);
            }

            if (algorithm is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.algorithm);
            }

            if (encryptionAlgorithm is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.encryptionAlgorithm);
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
        /// Wrap a key.
        /// </summary>
        /// <param name="staticKey">The key to be wrapped. If <c>null</c>, the key will be ephemeral and generated within this method.</param>
        /// <param name="header">The key-values representing the JWT header.</param>
        /// <param name="destination">The destination span.</param>
        public abstract SymmetricJwk WrapKey(Jwk? staticKey, JwtObject header, Span<byte> destination);

        /// <summary>
        /// Wrap a key.
        /// </summary>
        /// <param name="staticKey">The key to be wrapped. If <c>null</c>, the key will be ephemeral and generated within this method.</param>
        /// <param name="header">The key-values representing the JWT header.</param>
        /// <param name="destination">The destination span.</param>
        public abstract SymmetricJwk WrapKey(Jwk? staticKey, JwtHeaderX header, Span<byte> destination);

        /// <summary>
        /// Gets the size of the wrapped key.
        /// </summary>
        public abstract int GetKeyWrapSize();

        /// <summary>
        /// Creates a symmetric key based on the <paramref name="encryptionAlgorithm"/>, excepts if the <paramref name="staticKey"/> is defined.
        /// </summary>
        /// <param name="encryptionAlgorithm"></param>
        /// <param name="staticKey"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static SymmetricJwk CreateSymmetricKey(EncryptionAlgorithm encryptionAlgorithm, SymmetricJwk? staticKey)
        {
            return staticKey ?? SymmetricJwk.GenerateKey(encryptionAlgorithm.RequiredKeySizeInBits);
        }
    }
}
