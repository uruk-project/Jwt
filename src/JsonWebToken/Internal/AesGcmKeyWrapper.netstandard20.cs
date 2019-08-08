// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.
#if !NETCOREAPP3_0
using System;

namespace JsonWebToken.Internal
{
    internal sealed class AesGcmKeyWrapper : KeyWrapper
    {
        public AesGcmKeyWrapper(SymmetricJwk key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
            : base(key, encryptionAlgorithm, algorithm)
        {
            throw new NotSupportedException();
        }

        /// <inheritsdoc />
        public override int GetKeyUnwrapSize(int wrappedKeySize)
        {
            throw new NotSupportedException();
        }

        /// <inheritsdoc />
        public override int GetKeyWrapSize() => GetKeyWrapSize(EncryptionAlgorithm);

        public static int GetKeyWrapSize(EncryptionAlgorithm encryptionAlgorithm) => throw new NotSupportedException();

        /// <inheritsdoc />
        public override bool TryUnwrapKey(ReadOnlySpan<byte> keyBytes, Span<byte> destination, JwtHeader header, out int bytesWritten)
        {
            throw new NotSupportedException();
        }

        /// <inheritsdoc />
        public override void WrapKey(Jwk staticKey, JwtObject header, Span<byte> destination, out Jwk contentEncryptionKey, out int bytesWritten)
        {
            throw new NotSupportedException();
        }

        /// <inheritsdoc />
        protected override void Dispose(bool disposing)
        {
        }
    }
}
#endif