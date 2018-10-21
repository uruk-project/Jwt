﻿// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using Newtonsoft.Json.Linq;
using System;

namespace JsonWebToken.Internal
{
    public class RequiredClaimValidation<TClaim> : IValidation
    {
        private readonly string _claim;
        private readonly TClaim _value;

        public RequiredClaimValidation(string claim) : this(claim, default)
        {
        }

        public RequiredClaimValidation(string claim, TClaim value)
        {
            _claim = claim ?? throw new ArgumentNullException(nameof(claim));
            _value = value;
        }

        public TokenValidationResult TryValidate(in TokenValidationContext context)
        {
            var jwt = context.Jwt;
            var claim = jwt.Payload[_claim];
            if (claim == null || claim.Type == JTokenType.Null)
            {
                return TokenValidationResult.MissingClaim(jwt, _claim);
            }

            if (_value != default && !_value.Equals(claim.Value<TClaim>()))
            {
                return TokenValidationResult.InvalidClaim(jwt, _claim);
            }

            return TokenValidationResult.Success(jwt);
        }
    }
}
