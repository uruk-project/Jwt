// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.ComponentModel;

namespace JsonWebToken.Internal
{
    /// <summary>
    /// Represents a <see cref="IValidator"/> verifying the JWT has a required claim.
    /// </summary>
    /// <typeparam name="TClaim"></typeparam>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public class RequiredClaimValidator<TClaim> : IValidator
    {
        private readonly string _claim;
        private readonly TClaim _value;

        /// <summary>
        /// Initializes an instance of <see cref="RequiredClaimValidator{TClaim}"/>.
        /// </summary>
        /// <param name="claim"></param>
        public RequiredClaimValidator(string claim)
            : this(claim, default)
        {
        }

        /// <summary>
        /// Initializes an instance of <see cref="RequiredClaimValidator{TClaim}"/>.
        /// </summary>
        /// <param name="claim"></param>
        /// <param name="value"></param>
        public RequiredClaimValidator(string claim, TClaim value)
        {
            _claim = claim ?? throw new ArgumentNullException(nameof(claim));
            _value = value;
        }

        /// <inheritdoc />
        public TokenValidationResult TryValidate(in TokenValidationContext context)
        {
            var jwt = context.Jwt;
            var claim = jwt.Payload[_claim];
            if (claim == null)
            {
                return TokenValidationResult.MissingClaim(jwt, _claim);
            }

            if (_value != default && !_value.Equals((TClaim)claim))
            {
                return TokenValidationResult.InvalidClaim(jwt, _claim);
            }

            return TokenValidationResult.Success(jwt);
        }
    }

    /// <summary>
    /// Represents a <see cref="IValidator"/> verifying the JWT has a required claim.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public class RequiredClaimValidator : IValidator
    {
        private readonly string _claim;

        /// <summary>
        /// Initializes an instance of <see cref="RequiredClaimValidator{TClaim}"/>.
        /// </summary>
        /// <param name="claim"></param>
        public RequiredClaimValidator(string claim)
        {
            _claim = claim;
        }

        /// <inheritdoc />
        public TokenValidationResult TryValidate(in TokenValidationContext context)
        {
            var jwt = context.Jwt;
            if (jwt.Payload.ContainsKey(_claim))
            {
                return TokenValidationResult.Success(jwt);
            }

            return TokenValidationResult.MissingClaim(jwt, _claim);
        }
    }
}
