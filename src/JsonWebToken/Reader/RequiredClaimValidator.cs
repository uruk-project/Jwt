// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Diagnostics.CodeAnalysis;

namespace JsonWebToken
{
    /// <summary>Represents a <see cref="IValidator"/> verifying the JWT has a required claim.</summary>
    internal sealed class RequiredClaimValidator : IValidator
    {
        private readonly string _claim;

        /// <summary>Initializes an instance of <see cref="RequiredClaimValidator"/>.</summary>
        public RequiredClaimValidator(string claim)
        {
            _claim = claim;
        }

        public bool TryValidate(JwtHeaderDocument header, JwtPayloadDocument payload, [NotNullWhen(false)] out TokenValidationError? error)
        {
            if (payload is null)
            {
                error = TokenValidationError.MalformedToken();
                return false;
            }

            if (payload.ContainsClaim(_claim))
            {
                error = null;
                return true;
            }

            error = TokenValidationError.MissingClaim(_claim);
            return false;
        }
    }
}