// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    /// <summary>
    /// https://tools.ietf.org/html/draft-bradley-oauth-jwt-encoded-state-09
    /// </summary>
    public class StateDescriptor : JwsDescriptor
    {
        public StateDescriptor(SignatureAlgorithm alg, Jwk signingKey)
            : base(signingKey, alg)
        {
        }

        public override void Validate()
        {
            base.Validate();

            CheckRequiredClaimAsString(OAuth2Claims.Rfp);
        }
    }
}
