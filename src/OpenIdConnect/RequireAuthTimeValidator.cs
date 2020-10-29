// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;

namespace JsonWebToken
{
    /// <summary>
    /// Represents a <see cref="IValidator"/> verifying the JWT has a required claim.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public sealed class RequireAuthTimeValidator : IValidator
    {
        /// <inheritdoc />
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

            if (jwt.Payload.ContainsClaim(OidcClaims.AuthTimeUtf8))
            {
                return TokenValidationResult.Success(jwt);
            }

            return TokenValidationResult.MissingClaim(jwt, OidcClaims.AuthTimeUtf8);
        }

        public bool TryValidate(JwtHeaderDocument header, JwtPayloadDocument payload, [NotNullWhen(false)] out TokenValidationError? error)
        {
            if (payload is null)
            {
                error = TokenValidationError.MalformedToken();
                return false;
            }

            if (payload.ContainsClaim(OidcClaims.AuthTimeUtf8))
            {
                error = null;
                return true;
            }

            error = TokenValidationError.MissingClaim(OidcClaims.AuthTimeUtf8);
            return false;
        }
    }
}
