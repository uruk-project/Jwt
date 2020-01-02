// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.ComponentModel;

namespace JsonWebToken
{
    /// <summary>
    /// Represents a <see cref="IValidator"/> verifying the JWT has a required claim.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public sealed class RequireAuthTimeValidator : IValidator
    {
        /// <inheritdoc />
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

            if (jwt.Payload.TryGetValue(OidcClaims.AuthTimeUtf8, out var _))
            {
                return TokenValidationResult.Success(jwt);
            }

            return TokenValidationResult.MissingClaim(jwt, OidcClaims.AuthTimeUtf8);
        }
    }
}
