// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Diagnostics;

namespace JsonWebToken.Cryptography
{
    internal sealed class DirectKeyUnwrapper : KeyUnwrapper
    {
        public DirectKeyUnwrapper(Jwk key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
            : base( encryptionAlgorithm, algorithm)
        {
            Debug.Assert(key.SupportKeyManagement(algorithm));
            Debug.Assert(algorithm.Category == AlgorithmCategory.Direct);
        }

        public override int GetKeyUnwrapSize(int wrappedKeySize)
            => wrappedKeySize;

        public override bool TryUnwrapKey(ReadOnlySpan<byte> keyBytes, Span<byte> destination, JwtHeaderDocument header, out int bytesWritten)
        {
            keyBytes.CopyTo(destination);
            bytesWritten = keyBytes.Length;
            return true;
        }

        protected override void Dispose(bool disposing)
        {
        }
    }
}
