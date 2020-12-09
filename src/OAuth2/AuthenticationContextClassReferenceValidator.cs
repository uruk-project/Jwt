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

        public bool TryValidate(JwtHeaderDocument header, JwtPayloadDocument payload, [NotNullWhen(false)] out TokenValidationError? error)
        {
            if (payload is null)
            {
                error = TokenValidationError.MalformedToken();
                return false;
            }

            if (!payload.TryGetClaim(OAuth2Claims.Acr.EncodedUtf8Bytes, out var property))
            {
                error = TokenValidationError.MissingClaim(OAuth2Claims.Acr.ToString());
                return false;
            }

            if (!property.ValueEquals(_requiredAcr))
            {
                error = TokenValidationError.InvalidClaim(OAuth2Claims.Acr.ToString());
                return false;
            }

            error = null;
            return true;
        }
    }
}
