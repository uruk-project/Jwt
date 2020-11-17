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
        public bool TryValidate(JwtHeaderDocument header, JwtPayloadDocument payload, [NotNullWhen(false)] out TokenValidationError? error)
        {
            if (payload is null)
            {
                error = TokenValidationError.MalformedToken();
                return false;
            }

            if (payload.ContainsClaim(OidcClaims.AuthTime.EncodedUtf8Bytes))
            {
                error = null;
                return true;
            }

            error = TokenValidationError.MissingClaim(OidcClaims.AuthTime.ToString());
            return false;
        }
    }
}
