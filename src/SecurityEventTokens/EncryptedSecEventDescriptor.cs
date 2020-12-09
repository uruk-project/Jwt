// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    /// <summary>Defines an encrypted Security Event Token. <seealso cref="SecEventDescriptor"/> for signed Security Event Token.</summary>
    public sealed class EncryptedSecEventDescriptor : JweDescriptorBase<SecEventDescriptor>
    {
        public EncryptedSecEventDescriptor(Jwk encryptionKey, KeyManagementAlgorithm alg, EncryptionAlgorithm enc, CompressionAlgorithm? zip = null, string? typ = null, string? cty = null)
            : base(encryptionKey, alg, enc, zip, typ, cty)
        {
        }
    }
}
