// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Buffers;

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
        /// <param name="bufferWriter"></param>
        /// <param name="headerCache"></param>
        /// <param name="tokenLifetimeInSeconds"></param>
        /// <param name="generateIssuedTime"></param>
        public EncodingContext(IBufferWriter<byte> bufferWriter, JsonHeaderCache? headerCache, int tokenLifetimeInSeconds, bool generateIssuedTime)
        {
            BufferWriter = bufferWriter;
            HeaderCache = headerCache;
            TokenLifetimeInSeconds = tokenLifetimeInSeconds;
            GenerateIssuedTime = generateIssuedTime;
        }

        /// <summary>
        /// Gets the <see cref="IBufferWriter{T}"/> used to write data.
        /// </summary>
        public IBufferWriter<byte> BufferWriter { get; }

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