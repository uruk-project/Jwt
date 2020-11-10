// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Text.Json;
using JsonWebToken.Internal;

namespace JsonWebToken
{
    public class IdTokenDescriptor : JwsDescriptor
    {
        public IdTokenDescriptor(SignatureAlgorithm alg, Jwk signingKey)
            : base(signingKey, alg)
        {
        }

        public override void Validate()
        {
            CheckRequiredHeader(HeaderParameters.Alg, JsonValueKind.String);

            RequireClaim(Claims.Iss, JsonValueKind.String);
            RequireClaim(Claims.Sub, JsonValueKind.String);
            ValidateClaim(Claims.Aud, new[] { JsonValueKind.String, JsonValueKind.Array });
            RequireClaim(Claims.Exp, JsonValueKind.Number);
            RequireClaim(Claims.Iat, JsonValueKind.Number);
        }
    }
}
