// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    public sealed class EncryptedSecurityEventTokenDescriptor : JweDescriptor<SecurityEventTokenDescriptor>
    {
        public EncryptedSecurityEventTokenDescriptor(Jwk encryptionKey, KeyManagementAlgorithm alg, EncryptionAlgorithm enc, CompressionAlgorithm? zip = null) 
            : base(encryptionKey, alg, enc, zip)
        {
        }
    }
}
