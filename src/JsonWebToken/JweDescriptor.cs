// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    /// <summary>
    /// Defines an encrypted JWT with a <see cref="JwsDescriptor"/> payload.
    /// </summary>
    public sealed class JweDescriptor : JweDescriptor<JwsDescriptor>
    {
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
