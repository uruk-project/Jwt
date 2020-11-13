// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Text.Json;
using JsonWebToken.Internal;

namespace JsonWebToken
{
    /// <summary>Defines a signed ID token. <seealso cref="EncryptedIdTokenDescriptor"/> for encrypted ID token.</summary>
    public class IdTokenDescriptor : JwsDescriptor
    {
        public IdTokenDescriptor(SignatureAlgorithm alg, Jwk signingKey, string? typ = null, string? cty = null)
            : base(signingKey, alg, typ, cty)
        {
        }

        public override void Validate()
        {
            CheckRequiredHeader(HeaderParameters.Alg, JwtValueKind.String);

            RequireClaim(Claims.Iss, JwtValueKind.String);
            RequireClaim(Claims.Sub, JwtValueKind.String);
            ValidateClaim(Claims.Aud, JwtValueKind.String, JwtValueKind.Array);
            RequireClaim(Claims.Exp, JwtValueKind.Int64, JwtValueKind.Int32);
            RequireClaim(Claims.Iat, JwtValueKind.Int64, JwtValueKind.Int32);
        }
    }
}
