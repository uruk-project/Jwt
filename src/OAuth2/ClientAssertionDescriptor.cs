// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    /// <summary>
    /// https://tools.ietf.org/html/rfc7523#section-2.2
    /// </summary>
    public sealed class ClientAssertionDescriptor : JwsDescriptor
    {
        public ClientAssertionDescriptor(SignatureAlgorithm alg, Jwk signingKey)
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
