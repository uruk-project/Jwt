// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

namespace JsonWebToken.Internal
{
    public static class SymmetricKeyHelper
    {
        public static JsonWebKey CreateSymmetricKey(EncryptionAlgorithm encryptionAlgorithm, JsonWebKey staticKey)
        {
            if (staticKey != null)
            {
                return staticKey;
            }

            return SymmetricJwk.GenerateKey(encryptionAlgorithm.RequiredKeySizeInBytes << 3);
        }
    }
}