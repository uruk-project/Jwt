// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;

namespace JsonWebToken.Internal
{
    public class CriticalHeaderValidator : IValidator
    {
        public TokenValidationResult TryValidate(in TokenValidationContext context)
        {
            var jwt = context.Jwt;
            var crit = jwt.Header.Crit;
            if (crit == null || crit.Count == 0)
            {
                return TokenValidationResult.Success(jwt);
            }

            for (int i = 0; i < crit.Count; i++)
            {
                var criticalHeader = crit[i];
                if (!jwt.Header.ContainsKey(criticalHeader))
                {
                    return TokenValidationResult.CriticalHeaderMissing(criticalHeader, jwt);
                }
            }

            return TokenValidationResult.Success(jwt);
        }
    }

    public class AudienceValidator : IValidator
    {
        private readonly IEnumerable<string> _audiences;

        public AudienceValidator(IEnumerable<string> audiences)
        {
            _audiences = audiences;
        }

        /// <inheritsdoc />
        public TokenValidationResult TryValidate(in TokenValidationContext context)
        {
            var jwt = context.Jwt;
            bool missingAudience = true;
            foreach (string audience in jwt.Audiences)
            {
                missingAudience = false;
                if (string.IsNullOrWhiteSpace(audience))
                {
                    continue;
                }

                foreach (string validAudience in _audiences)
                {
                    if (string.Equals(audience, validAudience, StringComparison.Ordinal))
                    {
                        return TokenValidationResult.Success(jwt);
                    }
                }
            }

            if (missingAudience)
            {
                return TokenValidationResult.MissingClaim(jwt, Claims.Aud);
            }

            return TokenValidationResult.InvalidClaim(jwt, Claims.Aud);
        }
    }
}
