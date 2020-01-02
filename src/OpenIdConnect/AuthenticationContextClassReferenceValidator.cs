// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;

namespace JsonWebToken
{
    internal sealed class AuthenticationContextClassReferenceValidator : IValidator
    {
        private readonly string _requiredAcr;

        public AuthenticationContextClassReferenceValidator(string requiredAcr)
        {
            _requiredAcr = requiredAcr;
        }

        public TokenValidationResult TryValidate(Jwt jwt)
        {
            if (jwt is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.jwt);
            }

            if (jwt.Payload is null)
            {
                return TokenValidationResult.MalformedToken();
            }

            if (!jwt.Payload.TryGetValue(OidcClaims.AcrUtf8, out var property))
            {
                return TokenValidationResult.MissingClaim(jwt, OidcClaims.AcrUtf8);
            }

            if (string.Equals(_requiredAcr, (string?)property.Value, StringComparison.Ordinal))
            {
                return TokenValidationResult.InvalidClaim(jwt, OidcClaims.AcrUtf8);
            }

            return TokenValidationResult.Success(jwt);
        }
    }
}
