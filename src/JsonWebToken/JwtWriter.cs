// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.Text;

namespace JsonWebToken
{
    /// <summary>
    /// Writes a JWT.
    /// </summary>
    public sealed class JwtWriter
    {
        private readonly JsonHeaderCache _headerCache = new JsonHeaderCache();
        private int _tokenLifetimeInSeconds;

        /// <summary>
        /// Gets or sets the token lifetime in seconds.
        /// </summary>
        /// <remarks>Used by <see cref="WriteToken(JwtDescriptor)"/> to set the default expiration ('exp').</remarks>
        /// <exception cref="ArgumentOutOfRangeException">'value' less than 0.</exception>
        public int TokenLifetimeInSeconds
        {
            get
            {
                return _tokenLifetimeInSeconds;
            }

            set
            {
                if (value < 0)
                {
                    ThrowHelper.ThrowArgumentOutOfRangeException_MustBeGreaterOrEqualToZero(ExceptionArgument.value, value);
                }

                _tokenLifetimeInSeconds = value;
            }
        }

        /// <summary>
        /// Gets or sets whether the <see cref="JwtDescriptor"/> has to be validated. Default value is <c>false</c>.
        /// </summary>
        public bool IgnoreTokenValidation { get; set; } = false;

        /// <summary>
        /// Gets or sets whether the JWT header will be cached. Default value is <c>true</c>.
        /// </summary>
        public bool EnableHeaderCaching { get; set; } = true;

        /// <summary>
        /// Gets or sets whether the issued time must be generated.
        /// </summary>
        public bool GenerateIssuedTime { get; set; }

        /// <summary>
        /// Writes a JWT in its compact serialization format.
        /// </summary>
        /// <param name="descriptor">The descriptor of the JWT.</param>
        /// <returns>The array of <see cref="byte"/> representation of the JWT.</returns>
        public byte[] WriteToken(JwtDescriptor descriptor)
        {
            using var bufferWriter = new PooledByteBufferWriter();
            WriteToken(descriptor, bufferWriter);
            return bufferWriter.WrittenSpan.ToArray();
        }

        /// <summary>
        /// Writes a JWT in its compact serialization format.
        /// </summary>
        /// <param name="descriptor">The descriptor of the JWT.</param>
        /// <param name="output">The <see cref="IBufferWriter{T}"/> used for writing the output.</param>
        /// <returns>The array of <see cref="byte"/> representation of the JWT.</returns>
        public void WriteToken(JwtDescriptor descriptor, IBufferWriter<byte> output)
        {
            if (descriptor is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.descriptor);
            }

            if (!IgnoreTokenValidation)
            {
                descriptor.Validate();
            }

            var encodingContext = new EncodingContext(EnableHeaderCaching ? _headerCache : null, TokenLifetimeInSeconds, GenerateIssuedTime);
            descriptor.Encode(encodingContext, output);
        }

        /// <summary>
        /// Writes a JWT in its compact serialization format and returns it a string.
        /// </summary>
        /// <param name="descriptor">The descriptor of the JWT.</param>
        /// <returns>The <see cref="string"/> retpresention of the JWT.</returns>
        public string WriteTokenString(JwtDescriptor descriptor)
        {
            using var bufferWriter = new PooledByteBufferWriter();
            WriteToken(descriptor, bufferWriter);
#if NETSTANDARD2_0 || NET461
            return Encoding.UTF8.GetString(bufferWriter.WrittenSpan.ToArray());
#else
            return Encoding.UTF8.GetString(bufferWriter.WrittenSpan);
#endif
        }
    }
}
