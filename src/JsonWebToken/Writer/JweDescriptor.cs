// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    /// <summary>
    /// Defines an encrypted JWT with a <see cref="JwsDescriptor"/> payload.
    /// </summary>
    public sealed class JweDescriptor : JweDescriptorBase<JwsDescriptor>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="JweDescriptor"/> class.
        /// </summary>
        /// <param name="encryptionKey"></param>
        /// <param name="alg"></param>
        /// <param name="enc"></param>
        /// <param name="zip"></param>
        /// <param name="typ"></param>
        /// <param name="cty"></param>
        public JweDescriptor(Jwk encryptionKey, KeyManagementAlgorithm alg, EncryptionAlgorithm enc, CompressionAlgorithm? zip = null, string? typ = null, string? cty = Constants.Jwt)
            : base(encryptionKey, alg, enc, zip, typ, cty)
        {
        }
    }
}
