// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Diagnostics.CodeAnalysis;

namespace JsonWebToken.Internal
{
    /// <summary>
    /// Represents a <see cref="IValidator"/> verifying the JWT has a required claim.
    /// </summary>
    internal sealed class RequiredStringClaimValidator : IValidator
    {
        private readonly string _claim;
        private readonly string _value;

        /// <summary>
        /// Initializes an instance of <see cref="RequiredStringClaimValidator"/>.
        /// </summary>
        /// <param name="claim"></param>
        /// <param name="value"></param>
        public RequiredStringClaimValidator(string claim, string value)
        {
            if (claim is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.claim);
            }

            if (value is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.value);
            }

            _claim = claim;
            _value = value;
        }

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

            if (jwt.Payload.TryGetClaim(_claim, out var claim))
            {
                return TokenValidationResult.MissingClaim(jwt, _claim);
            }

            if (!claim.ValueEquals(_value))
            {
                return TokenValidationResult.InvalidClaim(jwt, _claim);
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

            if (!payload.TryGetClaim(_claim, out var claim))
            {
                error = TokenValidationError.MissingClaim(_claim);
                return false;
            }

            if (!claim.ValueEquals(_value))
            {
                error = TokenValidationError.InvalidClaim(_claim);
                return false;
            }

            error = null;
            return true;
        }
    }
}
