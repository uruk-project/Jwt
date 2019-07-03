// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;

namespace JsonWebToken.Internal
{
    internal sealed class IssuerValidation : IValidator
    {
        private readonly string _issuer;

        public IssuerValidation(string issuer)
        {
            _issuer = issuer;
        }

        public IssuerValidation()
        {
            _issuer = null;
        }

        public TokenValidationResult TryValidate(in TokenValidationContext context)
        {
            var jwt = context.Jwt;
            if (!jwt.Payload.TryGetValue(Claims.IssUtf8, out var property))
            {
                return TokenValidationResult.MissingClaim(jwt, Claims.IssUtf8);
            }

            if (_issuer != null && !string.Equals(_issuer, (string)property.Value, StringComparison.Ordinal))
            {
                return TokenValidationResult.InvalidClaim(jwt, Claims.IssUtf8);
            }

            return TokenValidationResult.Success(jwt);
        }
    }
}
