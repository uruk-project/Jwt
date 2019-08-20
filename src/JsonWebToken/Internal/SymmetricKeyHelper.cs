// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System.Runtime.CompilerServices;

namespace JsonWebToken.Internal
{
    internal static class SymmetricKeyHelper
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Jwk CreateSymmetricKey(EncryptionAlgorithm encryptionAlgorithm, Jwk? staticKey)
        {
            return staticKey ?? SymmetricJwk.GenerateKey(encryptionAlgorithm.RequiredKeySizeInBits);
        }
    }
}