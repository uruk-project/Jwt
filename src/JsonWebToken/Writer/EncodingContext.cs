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
        private static readonly DisabledJwtHeaderCache EmptyCache = new DisabledJwtHeaderCache();

        /// <summary>
        /// Initializes a new instance of the <see cref="EncodingContext"/> class.
        /// </summary>
        /// <param name="bufferWriter"></param>
        /// <param name="headerCache"></param>
        /// <param name="tokenLifetimeInSeconds"></param>
        /// <param name="generateIssuedTime"></param>
        public EncodingContext(IBufferWriter<byte> bufferWriter, IJwtHeaderCache? headerCache, int tokenLifetimeInSeconds, bool generateIssuedTime)
        {
            BufferWriter = bufferWriter;
            HeaderCache = headerCache ?? EmptyCache;
            TokenLifetimeInSeconds = tokenLifetimeInSeconds;
            GenerateIssuedTime = generateIssuedTime;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="EncodingContext"/> class.
        /// </summary>
        /// <param name="bufferWriter"></param>
        /// <param name="other"></param>
        public EncodingContext(IBufferWriter<byte> bufferWriter, EncodingContext other)
        {
            BufferWriter = bufferWriter;
            HeaderCache = other.HeaderCache;
            TokenLifetimeInSeconds = other.TokenLifetimeInSeconds;
            GenerateIssuedTime = other.GenerateIssuedTime;
        }

        /// <summary>
        /// Gets the <see cref="IBufferWriter{T}"/> used to write data.
        /// </summary>
        public IBufferWriter<byte> BufferWriter { get; }

        /// <summary>
        /// Gets the JSON header cache.
        /// </summary>
        public IJwtHeaderCache HeaderCache { get; }

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