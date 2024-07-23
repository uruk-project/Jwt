// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    /// <summary>
    /// https://datatracker.ietf.org/doc/html/rfc9068
    /// </summary>
    public sealed class AccessTokenDescriptor : JwsDescriptor
    {
  
        /// <summary>Initializes a new instance of <see cref="AccessTokenDescriptor"/> without signature, algorithm "none".</summary>
        /// <remarks>This descriptor does not manage signature, it cannot be considered as secure.</remarks>
        public AccessTokenDescriptor()
            : base(Jwk.None, SignatureAlgorithm.None, typ: "at+JWT")
        {
        }

        public AccessTokenDescriptor(SymmetricJwk signingKey, SymmetricSignatureAlgorithm alg)
            : base(signingKey, alg, typ: "at+JWT")
        {
        }

        public AccessTokenDescriptor(RsaJwk signingKey, RsaSignatureAlgorithm alg)
            : base(signingKey, alg, typ: "at+JWT")
        {
        }
        
        public AccessTokenDescriptor(ECJwk signingKey, ECSignatureAlgorithm alg)
            : base(signingKey, alg, typ: "at+JWT")
        {
        }

        public override void Validate()
        {
            CheckRequiredClaimAsString(JwtClaimNames.Iss);
            CheckRequiredClaimAsInteger(JwtClaimNames.Exp);
            CheckRequiredClaimAsStringOrArray(JwtClaimNames.Aud);
            CheckRequiredClaimAsString(JwtClaimNames.Sub);
            CheckRequiredClaimAsString(OAuth2Claims.ClientId);
            CheckRequiredClaimAsInteger(JwtClaimNames.Iat);
            CheckRequiredClaimAsString(JwtClaimNames.Jti);
        }
    }
}
