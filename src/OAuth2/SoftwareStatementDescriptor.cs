// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    /// <summary>https://tools.ietf.org/html/rfc7591#section-2.3</summary>
    public sealed class SoftwareStatementDescriptor : JwsDescriptor
    {
        /// <summary>Initializes a new instance of the <see cref="SoftwareStatementDescriptor"/> class.</summary>
        /// <remarks>This descriptor does not manage signature, it cannot be considered as secure.</remarks>
        public SoftwareStatementDescriptor() 
            : base(Jwk.None, SignatureAlgorithm.None)
        {
        }

        /// <summary>Initializes a new instance of the <see cref="SoftwareStatementDescriptor"/> class.</summary>
        /// <param name="alg"></param>
        /// <param name="signingKey"></param>
        public SoftwareStatementDescriptor(SymmetricSignatureAlgorithm alg, SymmetricJwk signingKey) 
            : base(signingKey, alg)
        {
        }

        /// <summary>Initializes a new instance of the <see cref="SoftwareStatementDescriptor"/> class.</summary>
        /// <param name="alg"></param>
        /// <param name="signingKey"></param>
        public SoftwareStatementDescriptor(RsaSignatureAlgorithm alg, RsaJwk signingKey) 
            : base(signingKey, alg)
        {
        }
        
        /// <summary>Initializes a new instance of the <see cref="SoftwareStatementDescriptor"/> class.</summary>
        /// <param name="alg"></param>
        /// <param name="signingKey"></param>
        public SoftwareStatementDescriptor(ECSignatureAlgorithm alg, ECJwk signingKey) 
            : base(signingKey, alg)
        {
        }

        public override void Validate()
        {
            base.Validate();
            CheckRequiredClaimAsString(JwtClaimNames.Iss);
        }
    }
}
