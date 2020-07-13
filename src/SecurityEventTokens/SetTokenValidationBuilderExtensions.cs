// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    public static class SetTokenValidationBuilderExtensions
    {
        public static TokenValidationPolicyBuilder RequireSecurityEventToken(this TokenValidationPolicyBuilder builder)
        {
            if (builder == null)
            {
                throw new System.ArgumentNullException(nameof(builder));
            }

            builder.RequireClaim(SetClaims.EventsUtf8);

            return builder;
        }
    }
}