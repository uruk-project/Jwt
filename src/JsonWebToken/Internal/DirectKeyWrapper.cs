// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.
using System;

namespace JsonWebToken.Internal
{
    internal sealed class DirectKeyWrapper : KeyWrapper
    {
        public DirectKeyWrapper(Jwk key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
            : base(key, encryptionAlgorithm, algorithm)
        {
        }

        public override int GetKeyWrapSize() 
            => 0;

        public override Jwk WrapKey(Jwk? staticKey, JwtObject header, Span<byte> destination)
        {
            if (staticKey != null)
            {
                ThrowHelper.ThrowArgumentException_StaticKeyNotSupported();
            }

            ReadOnlySpan<byte> bytes = Key.AsSpan();
            return SymmetricJwk.FromSpan(bytes, false);
        }

        protected override void Dispose(bool disposing)
        {
        }
    }
}
