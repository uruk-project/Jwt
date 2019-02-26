// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using System;
using System.Buffers;
using System.Text;

namespace JsonWebToken
{
    /// <summary>
    /// Writes a JWT.
    /// </summary>
    public sealed class JwtWriter : IDisposable
    {
        private readonly SignerFactory _signatureFactory;
        private readonly KeyWrapperFactory _keyWrapFactory;
        private readonly AuthenticatedEncryptorFactory _authenticatedEncryptionFactory;
        private readonly JsonHeaderCache _headerCache;
        private readonly bool _disposeFactories;

        private int _tokenLifetimeInMinutes;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of <see cref="JwtWriter"/>.
        /// </summary>
        public JwtWriter() :
            this(new DefaultSignerFactory(), new DefaultKeyWrapperFactory(), new DefaultAuthenticatedEncryptorFactory(), new JsonHeaderCache())
        {
            _disposeFactories = true;
        }

        /// <summary>
        /// Initializes a new instance of <see cref="JwtWriter"/>.
        /// </summary>
        /// <param name="signerFactory"></param>
        /// <param name="keyWrapperFactory"></param>
        /// <param name="authenticatedEncryptorFactory"></param>
        public JwtWriter(
            SignerFactory signerFactory,
            KeyWrapperFactory keyWrapperFactory,
            AuthenticatedEncryptorFactory authenticatedEncryptorFactory)
            : this(signerFactory, keyWrapperFactory, authenticatedEncryptorFactory, null)
        {
        }

        /// <summary>
        /// Initializes a new instance of <see cref="JwtWriter"/>.
        /// </summary>
        /// <param name="signerFactory"></param>
        /// <param name="keyWrapperFactory"></param>
        /// <param name="authenticatedEncryptorFactory"></param>
        /// <param name="headerCache"></param>
        public JwtWriter(
            SignerFactory signerFactory,
            KeyWrapperFactory keyWrapperFactory,
            AuthenticatedEncryptorFactory authenticatedEncryptorFactory,
            JsonHeaderCache headerCache)
        {
            if (signerFactory == null)
            {
                Errors.ThrowArgumentNullException(ExceptionArgument.signerFactory);
            }

            if (keyWrapperFactory == null)
            {
                Errors.ThrowArgumentNullException(ExceptionArgument.keyWrapperFactory);
            }

            if (authenticatedEncryptorFactory == null)
            {
                Errors.ThrowArgumentNullException(ExceptionArgument.authenticatedEncryptorFactory);
            }

            _signatureFactory = signerFactory;
            _keyWrapFactory = keyWrapperFactory;
            _authenticatedEncryptionFactory = authenticatedEncryptorFactory;
            _headerCache = headerCache ?? new JsonHeaderCache();
        }

        /// <summary>
        /// Gets or sets the token lifetime in minutes.
        /// </summary>
        /// <remarks>Used by <see cref="WriteToken(JwtDescriptor)"/> to set the default expiration ('exp').</remarks>
        /// <exception cref="ArgumentOutOfRangeException">'value' less than 0.</exception>
        public int TokenLifetimeInMinutes
        {
            get
            {
                return _tokenLifetimeInMinutes;
            }

            set
            {
                if (value < 0)
                {
                    Errors.ThrowMustBeGreaterOrEqualToZero(ExceptionArgument.value, value);
                }

                _tokenLifetimeInMinutes = value;
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
            using (var bufferWriter = new ArrayBufferWriter<byte>())
            {
                WriteToken(descriptor, bufferWriter);
                return bufferWriter.WrittenSpan.ToArray();
            }
        }

        /// <summary>
        /// Writes a JWT in its compact serialization format.
        /// </summary>
        /// <param name="descriptor">The descriptor of the JWT.</param>
        /// <param name="output">The <see cref="IBufferWriter{T}"/> used for writing the output.</param>
        /// <returns>The array of <see cref="byte"/> representation of the JWT.</returns>
        public void WriteToken(JwtDescriptor descriptor, IBufferWriter<byte> output)
        {
            if (descriptor == null)
            {
                Errors.ThrowArgumentNullException(ExceptionArgument.descriptor);
            }

            if (_disposed)
            {
                Errors.ThrowObjectDisposed(GetType());
            }

            if (!IgnoreTokenValidation)
            {
                descriptor.Validate();
            }

            var encodingContext = new EncodingContext(_signatureFactory, _keyWrapFactory, _authenticatedEncryptionFactory, EnableHeaderCaching ? _headerCache : null, TokenLifetimeInMinutes, GenerateIssuedTime);
            descriptor.Encode(encodingContext, output);
        }

        /// <summary>
        /// Writes a JWT in its compact serialization format and returns it a string.
        /// </summary>
        /// <param name="descriptor">The descriptor of the JWT.</param>
        /// <returns>The <see cref="string"/> retpresention of the JWT.</returns>
        public string WriteTokenString(JwtDescriptor descriptor)
        {
            return Encoding.UTF8.GetString(WriteToken(descriptor));
        }

        /// <summary>
        /// Release the managed resources.
        /// </summary>
        public void Dispose()
        {
            if (!_disposed && _disposeFactories)
            {
                _authenticatedEncryptionFactory.Dispose();
                _signatureFactory.Dispose();
                _keyWrapFactory.Dispose();
                _disposed = true;
            }
        }
    }
}
