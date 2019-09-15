// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Runtime.CompilerServices;

namespace JsonWebToken
{
    /// <summary>
    /// Provides key wrapping and key unwrapping services.
    /// </summary>
    public abstract class KeyWrapper : IDisposable
    {
        /// <summary>
        /// Defines a <see cref="KeyWrapper"/> that do nothing.
        /// </summary>
        public static readonly KeyWrapper Empty = new EmptyKeyWrapper();

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
        /// Initializes a new instances of <see cref="KeyWrapper"/>.
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

            if (!key!.IsSupported(algorithm))
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

            Algorithm = algorithm!;
            EncryptionAlgorithm = encryptionAlgorithm!;
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
        public abstract Jwk WrapKey(Jwk? staticKey, JwtObject header, Span<byte> destination);

        /// <summary>
        /// Gets the size of the unwrapped key.
        /// </summary>
        public abstract int GetKeyUnwrapSize(int wrappedKeySize);

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
        public static Jwk CreateSymmetricKey(EncryptionAlgorithm encryptionAlgorithm, Jwk? staticKey)
        {
            return staticKey ?? SymmetricJwk.GenerateKey(encryptionAlgorithm.RequiredKeySizeInBits);
        }

        internal class EmptyKeyWrapper : KeyWrapper
        {
            // TODO : Add Empty EncryptionAlgorithm & KeyManagementAlgorithm
            public EmptyKeyWrapper()
                : base(Jwk.Empty, EncryptionAlgorithm.Empty, KeyManagementAlgorithm.Empty)
            {
            }

            public override int GetKeyUnwrapSize(int wrappedKeySize) => 0;

            public override int GetKeyWrapSize() => 0;

            public override bool TryUnwrapKey(ReadOnlySpan<byte> keyBytes, Span<byte> destination, JwtHeader header, out int bytesWritten)
            {
                bytesWritten = 0;
                return true;
            }

            public override Jwk WrapKey(Jwk? staticKey, JwtObject header, Span<byte> destination)
            {
                return Jwk.Empty;
            }

            protected override void Dispose(bool disposing)
            {
            }
        }
    }
}
