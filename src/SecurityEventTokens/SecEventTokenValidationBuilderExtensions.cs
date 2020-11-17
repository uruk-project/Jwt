// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    public static class SecEventTokenValidationBuilderExtensions
    {
        /// <summary>
        /// Requires a JWT representing a SECEVENT, verify the presence of the 'events' claim.
        /// </summary>
        /// <param name="builder"></param>
        /// <returns></returns>
        public static TokenValidationPolicyBuilder RequireSecEventToken(this TokenValidationPolicyBuilder builder)
        {
            if (builder == null)
            {
                throw new System.ArgumentNullException(nameof(builder));
            }

            builder.RequireClaim(SecEventClaims.Events.ToString());

            return builder;
        }
    }
}