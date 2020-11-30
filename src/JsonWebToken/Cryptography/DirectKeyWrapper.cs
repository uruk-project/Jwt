// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Diagnostics;

namespace JsonWebToken.Cryptography
{
    internal sealed class DirectKeyWrapper : KeyWrapper
    {
        public DirectKeyWrapper(Jwk key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
            : base(key, encryptionAlgorithm, algorithm)
        {
            Debug.Assert(typeof(SymmetricJwk) == key.GetType());
        }

        public override int GetKeyWrapSize()
            => 0;

        public override SymmetricJwk WrapKey(Jwk? staticKey, JwtHeader header, Span<byte> destination)
        {
            Debug.Assert(staticKey is null, "Direct encryption does not support the use of static key.");
            return (SymmetricJwk)Key;
        }

        protected override void Dispose(bool disposing)
        {
        }
    }
}
