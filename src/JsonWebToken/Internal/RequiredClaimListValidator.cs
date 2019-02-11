// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

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
    [EditorBrowsable(EditorBrowsableState.Never)]
    public sealed class RequiredClaimListValidator<TClaim> : IValidator
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
            _claim = claim ?? throw new ArgumentNullException(nameof(claim));
            _values = values ?? throw new ArgumentNullException(nameof(values));
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

            for (int i = 0; i < _values.Count; i++)
            {
                if (_values[i].Equals((TClaim)claim))
                {
                    return TokenValidationResult.Success(jwt);
                }
            }

            return TokenValidationResult.InvalidClaim(jwt, _claim);
        }
    }
}
