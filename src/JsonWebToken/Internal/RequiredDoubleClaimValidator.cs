// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Diagnostics.CodeAnalysis;

namespace JsonWebToken.Internal
{
    /// <summary>
    /// Represents a <see cref="IValidator"/> verifying the JWT has a required claim.
    /// </summary>
    internal sealed class RequiredDoubleClaimValidator : IValidator
    {
        private readonly string _claim;
        private readonly double? _value;

        /// <summary>
        /// Initializes an instance of <see cref="RequiredDoubleClaimValidator"/>.
        /// </summary>
        /// <param name="claim"></param>
        public RequiredDoubleClaimValidator(string claim)
            : this(claim, null)
        {
        }

        /// <summary>
        /// Initializes an instance of <see cref="RequiredDoubleClaimValidator"/>.
        /// </summary>
        /// <param name="claim"></param>
        /// <param name="value"></param>
        public RequiredDoubleClaimValidator(string claim, double? value)
        {
            if (claim is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.claim);
            }

            _claim = claim;
            _value = value;
        }

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

            var claim = jwt.Payload[_claim];
            if (claim is null)
            {
                return TokenValidationResult.MissingClaim(jwt, _claim);
            }

            if (_value != (double?)claim)
            {
                return TokenValidationResult.InvalidClaim(jwt, _claim);
            }

            return TokenValidationResult.Success(jwt);
        }

        public bool TryValidate(JwtHeader header, JwtPayload payload, [NotNullWhen(false)] out TokenValidationError? error)
        {
            if (payload is null)
            {
                error = TokenValidationError.MalformedToken();
                return false;
            }

            var claim = payload[_claim];
            if (claim is null)
            {
                error = TokenValidationError.MissingClaim(_claim);
                return false;
            }

            if (_value != (double?)claim)
            {
                error = TokenValidationError.InvalidClaim(_claim);
                return false;
            }

            error = null;
            return true;
        }
    }
}
