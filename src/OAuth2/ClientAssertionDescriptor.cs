// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    /// <summary>
    /// https://tools.ietf.org/html/rfc7523#section-2.2
    /// </summary>
    public sealed class ClientAssertionDescriptor : JwsDescriptor
    {
        /// <summary>Initializes a new instance of <see cref="ClientAssertionDescriptor"/> without signature, algorithm "none".</summary>
        /// <remarks>This descriptor does not manage signature, it cannot be considered as secure.</remarks>
        public ClientAssertionDescriptor()
            : base(Jwk.None, SignatureAlgorithm.None)
        {
        }

        public ClientAssertionDescriptor(SymmetricJwk signingKey, SymmetricSignatureAlgorithm alg)
            : base(signingKey, alg)
        {
        }
        
        public ClientAssertionDescriptor(RsaJwk signingKey, RsaSignatureAlgorithm alg)
            : base(signingKey, alg)
        {
        }

        public ClientAssertionDescriptor(ECJwk signingKey, ECSignatureAlgorithm alg)
            : base(signingKey, alg)
        {
        }

        public override void Validate()
        {
            base.Validate();

            CheckRequiredClaimAsString(JwtClaimNames.Iss);
            CheckRequiredClaimAsString(JwtClaimNames.Sub);
            CheckRequiredClaimAsStringOrArray(JwtClaimNames.Aud);
            CheckRequiredClaimAsInteger(JwtClaimNames.Exp);
        }
    }
}
