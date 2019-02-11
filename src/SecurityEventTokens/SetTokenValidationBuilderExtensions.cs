// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;

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