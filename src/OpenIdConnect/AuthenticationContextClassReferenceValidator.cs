// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Diagnostics.CodeAnalysis;

namespace JsonWebToken
{
    internal sealed class AuthenticationContextClassReferenceValidator : IValidator
    {
        private readonly string _requiredAcr;

        public AuthenticationContextClassReferenceValidator(string requiredAcr)
        {
            _requiredAcr = requiredAcr;
        }

        [Obsolete("This method is obsolete. Use TryValidate(JwtHeaderDocument header, JwtPayloadDocument payload, out TokenValidationError? error) instead.")]
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

            if (!jwt.Payload.TryGetClaim(OidcClaims.AcrUtf8, out var property))
            {
                return TokenValidationResult.MissingClaim(jwt, OidcClaims.AcrUtf8);
            }

            if (string.Equals(_requiredAcr, property.GetString(), StringComparison.Ordinal))
            {
                return TokenValidationResult.InvalidClaim(jwt, OidcClaims.AcrUtf8);
            }

            return TokenValidationResult.Success(jwt);
        }

        public bool TryValidate(JwtHeaderDocument header, JwtPayloadDocument payload, [NotNullWhen(false)] out TokenValidationError? error)
        {
            if (payload is null)
            {
                error = TokenValidationError.MalformedToken();
                return false;
            }

            if (!payload.TryGetClaim(OidcClaims.AcrUtf8, out var property))
            {
                error = TokenValidationError.MissingClaim(OidcClaims.AcrUtf8);
                return false;
            }

            if (!property.ValueEquals(_requiredAcr))
            {
                error = TokenValidationError.InvalidClaim(OidcClaims.AcrUtf8);
                return false;
            }

            error = null;
            return true;
        }
    }
}
