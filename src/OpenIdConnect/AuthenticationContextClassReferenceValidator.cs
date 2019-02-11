// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;

namespace JsonWebToken
{
    public sealed class AuthenticationContextClassReferenceValidator : IValidator
    {
        private readonly string _requiredAcr;

        public AuthenticationContextClassReferenceValidator(string requiredAcr)
        {
            _requiredAcr = requiredAcr;
        }

        public TokenValidationResult TryValidate(in TokenValidationContext context)
        {
            var jwt = context.Jwt;
            if (!jwt.Payload.TryGetValue(OidcClaims.AcrUtf8, out var property))
            {
                return TokenValidationResult.MissingClaim(jwt, OidcClaims.AcrUtf8);
            }

            if (string.Equals(_requiredAcr, (string)property.Value, StringComparison.Ordinal))
            {
                return TokenValidationResult.InvalidClaim(jwt, OidcClaims.AcrUtf8);
            }

            return TokenValidationResult.Success(jwt);
        }
    }
}
