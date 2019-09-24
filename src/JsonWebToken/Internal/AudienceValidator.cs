// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;

namespace JsonWebToken.Internal
{
    internal sealed class AudienceValidator : IValidator
    {
        private readonly IEnumerable<string> _audiences;

        public AudienceValidator(IEnumerable<string> audiences)
        {
            _audiences = audiences;
        }

        /// <inheritsdoc />
        public TokenValidationResult TryValidate(Jwt jwt)
        {
            if (jwt is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.jwt);
            }
            
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
                return TokenValidationResult.MissingClaim(jwt, Claims.AudUtf8);
            }

            return TokenValidationResult.InvalidClaim(jwt, Claims.AudUtf8);
        }
    }
}