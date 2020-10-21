// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

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
        public TokenValidationResult TryValidate(JwtOld jwt)
        {
            if (jwt is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.jwt);
            }

            if (jwt.Payload is null)
            {
                return TokenValidationResult.MalformedToken();
            }

            if (jwt.Payload.TryGetValue(OidcClaims.AuthTimeUtf8, out var _))
            {
                return TokenValidationResult.Success(jwt);
            }

            return TokenValidationResult.MissingClaim(jwt, OidcClaims.AuthTimeUtf8);
        }
        public bool TryValidate(JwtHeader header, JwtPayload payload, [NotNullWhen(false)] out TokenValidationError? error)
        {
            if (payload is null)
            {
                error = TokenValidationError.MalformedToken();
                return false;
            }

            if (payload.TryGetValue(OidcClaims.AuthTimeUtf8, out var _))
            {
                error = null;
                return true;
            }

            error = TokenValidationError.MissingClaim(OidcClaims.AuthTimeUtf8);
            return false;
        }

        public bool TryValidate(JwtHeader header, JwtPayloadDocument payload, [NotNullWhen(false)] out TokenValidationError? error)
        {
            if (payload is null)
            {
                error = TokenValidationError.MalformedToken();
                return false;
            }

            if (payload.TryGetProperty(OidcClaims.AuthTimeUtf8, out var _))
            {
                error = null;
                return true;
            }

            error = TokenValidationError.MissingClaim(OidcClaims.AuthTimeUtf8);
            return false;
        }

        public bool TryValidate(JwtHeaderDocument header, JwtPayloadDocumentOld payload, [NotNullWhen(false)] out TokenValidationError? error)
        {
            if (payload is null)
            {
                error = TokenValidationError.MalformedToken();
                return false;
            }

            if (payload.TryGetProperty(OidcClaims.AuthTimeUtf8, out var _))
            {
                error = null;
                return true;
            }

            error = TokenValidationError.MissingClaim(OidcClaims.AuthTimeUtf8);
            return false;
        }
    }
}
