// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;

namespace JsonWebToken
{
    /// <summary>Writes a JWT.</summary>
    public sealed class JwtWriter
    {
        private static readonly DisabledJwtHeaderCache _disabledCache = new DisabledJwtHeaderCache();

        private IJwtHeaderCache _headerCache = new LruJwtHeaderCache();
        private int _tokenLifetimeInSeconds;
        private bool _enableHeaderCaching = true;

        /// <summary>Gets or sets the token lifetime in seconds.</summary>
        /// <remarks>Used by <see cref="WriteToken(JwtDescriptor)"/> to set the default expiration ('exp').</remarks>
        /// <exception cref="ArgumentOutOfRangeException">'value' less than 0.</exception>
        public int TokenLifetimeInSeconds
        {
            get => _tokenLifetimeInSeconds;
            set
            {
                if (value < 0)
                {
                    ThrowHelper.ThrowArgumentOutOfRangeException_MustBeGreaterOrEqualToZero(ExceptionArgument.value, value);
                }

                _tokenLifetimeInSeconds = value;
            }
        }

        /// <summary>Gets or sets whether the <see cref="JwtDescriptor"/> has to be validated. Default value is <c>false</c>.</summary>
        public bool IgnoreTokenValidation { get; set; }

        /// <summary>Gets or sets whether the JWT header will be cached. Default value is <c>true</c>.</summary>
        public bool EnableHeaderCaching
        {
            get => _enableHeaderCaching;
            set
            {
                if (value & !_enableHeaderCaching)
                {
                    _headerCache = new LruJwtHeaderCache();
                }
                else if (!value & _enableHeaderCaching)
                {
                    _headerCache = _disabledCache;
                }

                _enableHeaderCaching = value;
            }
        }

        /// <summary>Gets or sets whether the issued time must be generated. Default value is <c>false</c>.</summary>
        public bool GenerateIssuedTime { get; set; }

        /// <summary>Writes a JWT in its compact serialization format.</summary>
        /// <param name="descriptor">The descriptor of the JWT.</param>
        /// <returns>The array of <see cref="byte"/> representation of the JWT.</returns>
        public byte[] WriteToken(JwtDescriptor descriptor)
        {
            using var bufferWriter = new PooledByteBufferWriter();
            WriteToken(descriptor, bufferWriter);
            return bufferWriter.WrittenSpan.ToArray();
        }

        /// <summary>Writes a JWT in its compact serialization format.</summary>
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

            var encodingContext = new EncodingContext(output, EnableHeaderCaching ? _headerCache : null, TokenLifetimeInSeconds, GenerateIssuedTime);
            descriptor.Encode(encodingContext);
        }

        /// <summary>Writes a JWT in its compact serialization format and returns it a string.</summary>
        /// <param name="descriptor">The descriptor of the JWT.</param>
        /// <returns>The <see cref="string"/> represention of the JWT.</returns>
        public string WriteTokenString(JwtDescriptor descriptor)
        {
            using var bufferWriter = new PooledByteBufferWriter();
            WriteToken(descriptor, bufferWriter);
            return Utf8.GetString(bufferWriter.WrittenSpan);
        }
    }
}
