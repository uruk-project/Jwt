// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Diagnostics;

namespace JsonWebToken.Cryptography
{
    internal sealed class DirectKeyWrapper : KeyWrapper
    {
        private readonly SymmetricJwk _key;

        public DirectKeyWrapper(SymmetricJwk key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
            : base(encryptionAlgorithm, algorithm)
        {
            Debug.Assert(key.SupportKeyManagement(algorithm));
            Debug.Assert(algorithm.Category == AlgorithmCategory.Direct);
            _key = key;
        }

        public override int GetKeyWrapSize()
            => 0;

        public override SymmetricJwk WrapKey(Jwk? staticKey, JwtHeader header, Span<byte> destination)
        {
            Debug.Assert(staticKey is null, "Direct encryption does not support the use of static key.");
            return _key;
        }

        protected override void Dispose(bool disposing)
        {
        }
    }
}
