// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;

namespace JsonWebToken
{
    public sealed partial class JweDescriptor
    {
        /// <summary>Initializes a new instance of the <see cref="JweDescriptor"/> class.</summary>
        [Obsolete("This constructor is obsolete. Use the constructor JweDescriptor(Jwk encryptionKey, KeyManagementAlgorithm alg, EncryptionAlgorithm enc, CompressionAlgorithm? zip = null, string? typ = null, string? cty = Constants.Jwt) instead.", true)]
        public JweDescriptor()
            : base(Jwk.None, KeyManagementAlgorithm.Create("obsolete"), EncryptionAlgorithm.Create("obsolete"), null, null)
            => throw new NotImplementedException();
    }
}
