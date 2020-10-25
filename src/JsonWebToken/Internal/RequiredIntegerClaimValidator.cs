﻿// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Diagnostics.CodeAnalysis;

namespace JsonWebToken.Internal
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

            var claim = jwt.Payload[_claim];
            if (claim is null)
            {
                return TokenValidationResult.MissingClaim(jwt, _claim);
            }

            if (_value != (long?)claim)
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

            if (_value != (long?)claim)
            {
                error = TokenValidationError.InvalidClaim(_claim);
                return false;
            }

            error = null;
            return true;
        }

        public bool TryValidate(JwtHeaderDocument2 header, JwtPayloadDocumentOld payload, [NotNullWhen(false)] out TokenValidationError? error)
        {
            if (payload is null)
            {
                error = TokenValidationError.MalformedToken();
                return false;
            }

            if (!payload.TryGetProperty(_claim, out var property))
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

        public bool TryValidate(JwtHeader header, JwtPayloadDocument payload, [NotNullWhen(false)] out TokenValidationError? error)
        {
            if (payload is null)
            {
                error = TokenValidationError.MalformedToken();
                return false;
            }

            if (!payload.TryGetProperty(_claim, out var property))
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

        public bool TryValidate(JwtHeaderDocument header, JwtPayloadDocument payload, [NotNullWhen(false)] out TokenValidationError? error)
        {
            if (payload is null)
            {
                error = TokenValidationError.MalformedToken();
                return false;
            }

            if (!payload.TryGetProperty(_claim, out var property))
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
