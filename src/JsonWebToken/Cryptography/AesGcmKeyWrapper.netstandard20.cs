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
            ThrowHelper.ThrowNotSupportedException_AlgorithmForKeyWrap(algorithm);
        }

        /// <inheritsdoc />
        public override int GetKeyWrapSize()
            => GetKeyWrapSize(EncryptionAlgorithm);

        public static int GetKeyWrapSize(EncryptionAlgorithm encryptionAlgorithm)
            => throw new NotImplementedException();

        /// <inheritsdoc />
        public override Jwk WrapKey(Jwk? staticKey, JwtObject header, Span<byte> destination) 
            => throw new NotImplementedException();

        /// <inheritsdoc />
        protected override void Dispose(bool disposing)
        {
        }
    }
}
#endif