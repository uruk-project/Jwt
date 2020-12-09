// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;

namespace JsonWebToken
{
    /// <summary>Defines an encrypted JWT with a <see cref="JwsDescriptor"/> payload.</summary>
    public sealed partial class JweDescriptor : JweDescriptorBase<JwsDescriptor>
    {
        /// <summary>Initializes a new instance of the <see cref="JweDescriptor"/> class.</summary>
        public JweDescriptor(Jwk encryptionKey, KeyManagementAlgorithm alg, EncryptionAlgorithm enc, CompressionAlgorithm? zip = null, string? typ = null, string? cty = Constants.Jwt)
            : base(encryptionKey, alg, enc, zip, typ, cty)
        {
        }
    }
}
