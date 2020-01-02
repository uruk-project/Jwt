// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Text;

namespace JsonWebToken.Internal
{
    /// <summary>
    /// Represents a <see cref="IValidator"/> verifying the JWT has a required claim.
    /// </summary>
    /// <typeparam name="TClaim"></typeparam>
    internal sealed class RequiredClaimListValidator<TClaim> : IValidator
    {
        private readonly string _claim;
        private readonly IList<TClaim> _values;

        /// <summary>
        /// Initializes an instance of <see cref="RequiredClaimListValidator{TClaim}"/>.
        /// </summary>
        /// <param name="claim"></param>
        /// <param name="values"></param>
        public RequiredClaimListValidator(string claim, IList<TClaim> values)
        {
            if (claim is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.claim);
            }

            if (values is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.values);
            }

            for (int i = 0; i < values.Count; i++)
            {
                if (values[i] is null)
                {
                    ThrowHelper.ThrowArgumentException_MustNotContainNull(ExceptionArgument.values);
                }
            }

            _claim = claim;
            _values = values;
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

            for (int i = 0; i < _values.Count; i++)
            {
                if (_values[i]!.Equals((TClaim)claim))
                {
                    return TokenValidationResult.Success(jwt);
                }
            }

            return TokenValidationResult.InvalidClaim(jwt, _claim);
        }
    }
}
