// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Diagnostics;

namespace JsonWebToken.Cryptography
{
    internal sealed class DirectKeyUnwrapper : KeyUnwrapper
    {
        private SymmetricJwk _key;

        public DirectKeyUnwrapper(SymmetricJwk key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
            : base( encryptionAlgorithm, algorithm)
        {
            Debug.Assert(algorithm.Category == AlgorithmCategory.Direct);
            _key = key;
        }

        public override int GetKeyUnwrapSize(int wrappedKeySize)
            => _key.Length;

        public override bool TryUnwrapKey(ReadOnlySpan<byte> keyBytes, Span<byte> destination, JwtHeaderDocument header, out int bytesWritten)
        {
            // Direct key encryption does not support key wrapping
            if (keyBytes.Length > 0)
            {
                bytesWritten = 0;
                return false;
            }

            _key.K.CopyTo(destination);
            bytesWritten = _key.K.Length;
            return true;
        }

        protected override void Dispose(bool disposing)
        {
        }
    }
}
