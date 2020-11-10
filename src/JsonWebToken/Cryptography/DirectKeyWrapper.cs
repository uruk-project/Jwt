// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

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

        public override SymmetricJwk WrapKey(Jwk? staticKey, JwtObject header, Span<byte> destination)
        {
            if (staticKey != null)
            {
                ThrowHelper.ThrowArgumentException_StaticKeyNotSupported();
            }

            // TODO : make a copy of the Jwk instead of a copy of the span
            ReadOnlySpan<byte> bytes = Key.AsSpan();
            return SymmetricJwk.FromSpan(bytes, false);
        }

        public override SymmetricJwk WrapKey(Jwk? staticKey, JwtHeader header, Span<byte> destination)
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
