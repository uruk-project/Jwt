// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

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

            return builder.AddValidator(new RequireAuthTimeValidator());
        }

        public static TokenValidationPolicyBuilder RequireNonce(this TokenValidationPolicyBuilder builder)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            return builder.AddValidator(new RequireNonceValidator());
        }
    }
}
