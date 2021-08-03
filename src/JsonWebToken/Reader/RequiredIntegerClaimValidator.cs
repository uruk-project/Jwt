// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;

namespace JsonWebToken
{
    /// <summary>Represents a <see cref="IValidator"/> verifying the JWT has a required claim.</summary>
    internal sealed class RequiredIntegerClaimValidator : IValidator
    {
        private readonly string _claim;
        private readonly long? _value;

        /// <summary>Initializes an instance of <see cref="RequiredIntegerClaimValidator"/>.</summary>
        public RequiredIntegerClaimValidator(string claim)
            : this(claim, null)
        {
        }

        /// <summary>Initializes an instance of <see cref="RequiredIntegerClaimValidator"/>.</summary>
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

#if NET5_0_OR_GREATER
            Unsafe.SkipInit(out error);
#else
            error = default;
#endif
            return true;
        }
    }
}
