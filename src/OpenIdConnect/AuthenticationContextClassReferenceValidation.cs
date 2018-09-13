// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken;
using JsonWebToken.Internal;
using Newtonsoft.Json.Linq;
using System;

namespace JsonWebToken
{
    public class AuthenticationContextClassReferenceValidation : IValidation
    {
        private readonly string _requiredAcr;

        public AuthenticationContextClassReferenceValidation(string requiredAcr)
        {
            _requiredAcr = requiredAcr;
        }

        public TokenValidationResult TryValidate(in TokenValidationContext context)
        {
            var jwt = context.Jwt;
            var act = jwt.Payload[Claims.Acr];
            if (act == null || act.Type == JTokenType.Null)
            {
                return TokenValidationResult.MissingClaim(jwt, Claims.Acr);
            }

            if (string.Equals(_requiredAcr, act.Value<string>(), StringComparison.Ordinal))
            {
                return TokenValidationResult.InvalidClaim(jwt, Claims.Acr);
            }

            return TokenValidationResult.Success(jwt);
        }
    }
}
