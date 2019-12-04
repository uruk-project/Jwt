// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

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
        /// <param name="tokenLifetimeInSeconds"></param>
        /// <param name="generateIssuedTime"></param>
        public EncodingContext(JsonHeaderCache? headerCache, int tokenLifetimeInSeconds, bool generateIssuedTime)
        {
            HeaderCache = headerCache;
            TokenLifetimeInSeconds = tokenLifetimeInSeconds;
            GenerateIssuedTime = generateIssuedTime;
        }

        /// <summary>
        /// Gets the JSON header cache.
        /// </summary>
        public JsonHeaderCache? HeaderCache { get; }

        /// <summary>
        /// Gets the token lifetime, in seconds.
        /// </summary>
        public int TokenLifetimeInSeconds { get; }

        /// <summary>
        /// Gets whether the issuance time must be generated.
        /// </summary>
        public bool GenerateIssuedTime { get; }
    }
}