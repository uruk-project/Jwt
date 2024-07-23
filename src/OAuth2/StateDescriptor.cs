// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    /// <summary>
    /// https://tools.ietf.org/html/draft-bradley-oauth-jwt-encoded-state-09
    /// </summary>
    public sealed class StateDescriptor : JwsDescriptor
    {
        /// <summary>Initializes a new instance of <see cref="StateDescriptor"/> without signature, algorithm "none".</summary>
        /// <remarks>This descriptor does not manage signature, it cannot be considered as secure.</remarks>
        public StateDescriptor()
            : base(Jwk.None, SignatureAlgorithm.None)
        {
        }

        public StateDescriptor(SymmetricSignatureAlgorithm alg, SymmetricJwk signingKey)
            : base(signingKey, alg)
        {
        }
        
        public StateDescriptor(RsaSignatureAlgorithm alg, RsaJwk signingKey)
            : base(signingKey, alg)
        {
        }
        
        public StateDescriptor(ECSignatureAlgorithm alg, ECJwk signingKey)
            : base(signingKey, alg)
        {
        }

        public override void Validate()
        {
            CheckRequiredClaimAsString(OAuth2Claims.Rfp);
        }
    }
}
