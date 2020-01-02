// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken.Internal
{
    /// <summary>
    /// Represents a <see cref="IValidator"/> verifying the JWT has a required claim.
    /// </summary>
    internal class RequiredClaimValidator : IValidator
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

            if (jwt.Payload.ContainsKey(_claim))
            {
                return TokenValidationResult.Success(jwt);
            }

            return TokenValidationResult.MissingClaim(jwt, _claim);
        }
    }
}