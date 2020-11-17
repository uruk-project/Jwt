// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    /// <summary>Defines a signed ID token. <seealso cref="EncryptedIdTokenDescriptor"/> for encrypted ID token.</summary>
    public class IdTokenDescriptor : JwsDescriptor
    {
        public IdTokenDescriptor(SignatureAlgorithm alg, Jwk signingKey, string? typ = null, string? cty = null)
            : base(signingKey, alg, typ, cty)
        {
        }

        /// <inheritdoc/>
        public override void Validate()
        {
            CheckRequiredClaimAsString(Claims.Iss);
            CheckRequiredClaimAsString(Claims.Sub);
            CheckRequiredClaimAsStringOrArray(Claims.Aud);
            CheckRequiredClaimAsInteger(Claims.Exp);
            CheckRequiredClaimAsInteger(Claims.Iat);
        }
    }
}
