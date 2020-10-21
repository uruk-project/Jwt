// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Diagnostics.CodeAnalysis;

namespace JsonWebToken.Internal
{
    /// <summary>
    /// Represents a <see cref="IValidator"/> verifying the JWT has a required claim.
    /// </summary>
    internal sealed class RequiredClaimValidator : IValidator
    {
        private readonly string _claim;

        /// <summary>
        /// Initializes an instance of <see cref="RequiredClaimValidator"/>.
        /// </summary>
        /// <param name="claim"></param>
        public RequiredClaimValidator(string claim)
        {
            _claim = claim;
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

            if (jwt.Payload.ContainsKey(_claim))
            {
                return TokenValidationResult.Success(jwt);
            }

            return TokenValidationResult.MissingClaim(jwt, _claim);
        }

        public bool TryValidate(JwtHeader header, JwtPayload payload, [NotNullWhen(false)] out TokenValidationError? error)
        {
            if (payload is null)
            {
                error = TokenValidationError.MalformedToken();
                return false;
            }

            if (payload.ContainsKey(_claim))
            {
                error = null;
                return true;
            }

            error = TokenValidationError.MissingClaim(_claim);
            return false;
        }

        public bool TryValidate(JwtHeaderDocument header, JwtPayloadDocumentOld payload, [NotNullWhen(false)] out TokenValidationError? error)
        {
            if (payload is null)
            {
                error = TokenValidationError.MalformedToken();
                return false;
            }

            if (payload.TryGetProperty(_claim, out _))
            {
                error = null;
                return true;
            }

            error = TokenValidationError.MissingClaim(_claim);
            return false;
        }
        public bool TryValidate(JwtHeader header, JwtPayloadDocument payload, [NotNullWhen(false)] out TokenValidationError? error)
        {
            if (payload is null)
            {
                error = TokenValidationError.MalformedToken();
                return false;
            }

            if (payload.ContainsKey(_claim))
            {
                error = null;
                return true;
            }

            error = TokenValidationError.MissingClaim(_claim);
            return false;
        }
    }
}