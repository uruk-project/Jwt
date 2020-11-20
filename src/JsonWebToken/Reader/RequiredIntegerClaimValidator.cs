// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Diagnostics.CodeAnalysis;

namespace JsonWebToken
{
    /// <summary>
    /// Represents a <see cref="IValidator"/> verifying the JWT has a required claim.
    /// </summary>
    internal sealed class RequiredIntegerClaimValidator : IValidator
    {
        private readonly string _claim;
        private readonly long? _value;

        /// <summary>
        /// Initializes an instance of <see cref="RequiredIntegerClaimValidator"/>.
        /// </summary>
        /// <param name="claim"></param>
        public RequiredIntegerClaimValidator(string claim)
            : this(claim, null)
        {
        }

        /// <summary>
        /// Initializes an instance of <see cref="RequiredIntegerClaimValidator"/>.
        /// </summary>
        /// <param name="claim"></param>
        /// <param name="value"></param>
        public RequiredIntegerClaimValidator(string claim, long? value)
        {
            if (claim is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.claim);
            }

            _claim = claim;
            _value = value;
        }

        /// <inheritdoc/>
        public bool TryValidate(JwtHeaderDocument header, JwtPayloadDocument payload, [NotNullWhen(false)] out TokenValidationError? error)
        {
            if (payload is null)
            {
                error = TokenValidationError.MalformedToken();
                return false;
            }

            if (!payload.TryGetClaim(_claim, out var property))
            {
                error = TokenValidationError.MissingClaim(_claim);
                return false;
            }

            if (!property.TryGetInt64(out var claim) || _value != claim)
            {
                error = TokenValidationError.InvalidClaim(_claim);
                return false;
            }

            error = null;
            return true;
        }
    }
}
