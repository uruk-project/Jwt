// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System.Runtime.CompilerServices;

namespace JsonWebToken.Internal
{
    internal static class SymmetricKeyHelper
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static JsonWebKey CreateSymmetricKey(EncryptionAlgorithm encryptionAlgorithm, JsonWebKey staticKey)
        {
            return staticKey ?? SymmetricJwk.GenerateKey(encryptionAlgorithm.RequiredKeySizeInBytes << 3);
        }
    }
}