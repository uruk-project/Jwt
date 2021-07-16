// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    /// <summary>
    /// https://tools.ietf.org/html/draft-ietf-oauth-access-token-jwt-10
    /// </summary>
    public sealed class AccessTokenDescriptor : JwsDescriptor
    {
        public AccessTokenDescriptor(SignatureAlgorithm alg, Jwk signingKey)
            : base(signingKey, alg)
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
