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
            base.Validate();

            CheckRequiredClaimAsString(Claims.Iss);
            CheckRequiredClaimAsInteger(Claims.Exp);
            CheckRequiredClaimAsStringOrArray(Claims.Aud);
            CheckRequiredClaimAsString(Claims.Sub);
            CheckRequiredClaimAsString(OAuth2Claims.ClientId);
            CheckRequiredClaimAsInteger(Claims.Iat);
            CheckRequiredClaimAsString(Claims.Jti);
        }
    }
}
