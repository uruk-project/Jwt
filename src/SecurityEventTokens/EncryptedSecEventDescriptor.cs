// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    public sealed class EncryptedSecEventDescriptor : JweDescriptorBase<SecEventDescriptor>
    {
        public EncryptedSecEventDescriptor(Jwk encryptionKey, KeyManagementAlgorithm alg, EncryptionAlgorithm enc, CompressionAlgorithm? zip = null) 
            : base(encryptionKey, alg, enc, zip)
        {
        }
    }
}
