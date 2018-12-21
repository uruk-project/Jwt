// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using Newtonsoft.Json.Linq;
using System;

namespace JsonWebToken
{
    public class AuthenticationContextClassReferenceValidator : IValidator
    {
        private readonly string _requiredAcr;

        public AuthenticationContextClassReferenceValidator(string requiredAcr)
        {
            _requiredAcr = requiredAcr;
        }

        public TokenValidationResult TryValidate(in TokenValidationContext context)
        {
            var jwt = context.Jwt;
            var act = jwt.Payload[OidcClaims.Acr];
            if (act == null)
            {
                return TokenValidationResult.MissingClaim(jwt, OidcClaims.Acr);
            }

            if (string.Equals(_requiredAcr, (string)act, StringComparison.Ordinal))
            {
                return TokenValidationResult.InvalidClaim(jwt, OidcClaims.Acr);
            }

            return TokenValidationResult.Success(jwt);
        }
    }
}
