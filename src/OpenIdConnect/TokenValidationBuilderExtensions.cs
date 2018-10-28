// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using System;

namespace JsonWebToken
{
    public static class TokenValidationBuilderExtensions
    {
        public static TokenValidationPolicyBuilder RequireAuthenticationContextClassReference(this TokenValidationPolicyBuilder builder, string requiredAcr)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            return builder.AddValidator(new AuthenticationContextClassReferenceValidator(requiredAcr));
        }

        public static TokenValidationPolicyBuilder RequireAuthTime(this TokenValidationPolicyBuilder builder)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            return builder.AddValidator(new RequiredClaimValidator<int>(Claims.AuthTime));
        }

        public static TokenValidationPolicyBuilder RequireNonce(this TokenValidationPolicyBuilder builder)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            return builder.AddValidator(new RequiredClaimValidator<string>(Claims.Nonce));
        }
    }
}
