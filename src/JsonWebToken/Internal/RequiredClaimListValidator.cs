// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.ComponentModel;

namespace JsonWebToken.Internal
{
    [EditorBrowsable(EditorBrowsableState.Never)]
    public sealed class RequiredClaimListValidator<TClaim> : IValidator
    {
        private readonly string _claim;
        private readonly IList<TClaim> _values;

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
            if (claim == null || claim.Type == JTokenType.Null)
            {
                return TokenValidationResult.MissingClaim(jwt, _claim);
            }

            for (int i = 0; i < _values.Count; i++)
            {                
                if (_values[i].Equals(claim.Value<TClaim>()))
                {
                    return TokenValidationResult.Success(jwt);
                }
            }

            return TokenValidationResult.InvalidClaim(jwt, _claim);
        }
    }
}
