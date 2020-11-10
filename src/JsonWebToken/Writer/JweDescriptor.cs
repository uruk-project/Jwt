// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    /// <summary>
    /// Defines an encrypted JWT with a <see cref="JwsDescriptor"/> payload.
    /// </summary>
    public sealed class JweDescriptor : JweDescriptor<JwsDescriptor>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="JweDescriptor"/> class.
        /// </summary>
        /// <param name="encryptionKey"></param>
        /// <param name="alg"></param>
        /// <param name="enc"></param>
        /// <param name="zip"></param>
        public JweDescriptor(Jwk encryptionKey, KeyManagementAlgorithm alg, EncryptionAlgorithm enc, CompressionAlgorithm? zip = null)
            : base(encryptionKey, alg, enc, zip)
        {
        }

        /// <inheritsdoc />
        public override void Validate()
        {
            base.Validate();

            // It will be verified afterward
            //CheckRequiredHeader(HeaderParameters.Alg, JsonValueKind.String);
            //CheckRequiredHeader(HeaderParameters.Enc, JsonValueKind.String);
        }
    }
}
