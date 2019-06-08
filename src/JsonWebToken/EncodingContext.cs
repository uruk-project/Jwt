// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;

namespace JsonWebToken
{
    /// <summary>
    /// Encapsulate the context required for a JWT encoding.
    /// </summary>
    public sealed class EncodingContext
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="EncodingContext"/> class.
        /// </summary>
        /// <param name="headerCache"></param>
        /// <param name="tokenLifetimeInMinutes"></param>
        /// <param name="generateIssuedTime"></param>
        public EncodingContext(JsonHeaderCache headerCache, int tokenLifetimeInMinutes, bool generateIssuedTime)
        {
            HeaderCache = headerCache;
            TokenLifetimeInMinutes = tokenLifetimeInMinutes;
            GenerateIssuedTime = generateIssuedTime;
        }

        /// <summary>
        /// Gets the JSON header cache.
        /// </summary>
        public JsonHeaderCache HeaderCache { get; }

        /// <summary>
        /// Gets the token lifetime, in minutes.
        /// </summary>
        public int TokenLifetimeInMinutes { get; }

        /// <summary>
        /// Gets whether the issuance time must be generated.
        /// </summary>
        public bool GenerateIssuedTime { get; }
    }
}