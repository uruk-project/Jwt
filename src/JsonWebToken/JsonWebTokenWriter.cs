using System;

namespace JsonWebToken
{
    public sealed class JsonWebTokenWriter : IDisposable
    {
        private int _defaultTokenLifetimeInMinutes = DefaultTokenLifetimeInMinutes;

        /// <summary>
        /// Default lifetime of tokens created. When creating tokens, if 'exp' and 'nbf' are both null, then a default will be set to: exp = DateTime.UtcNow, nbf = DateTime.UtcNow + TimeSpan.FromMinutes(TokenLifetimeInMinutes).
        /// </summary>
        public static readonly int DefaultTokenLifetimeInMinutes = 60;
        private readonly ISignerFactory _signatureFactory;
        private readonly IKeyWrapperFactory _keyWrapFactory;
        private readonly IAuthenticatedEncryptorFactory _authenticatedEncryptionFactory;
        private JsonHeaderCache _headerCache;
        private readonly bool _disposeFactories;
        private bool _disposed;

        public JsonWebTokenWriter() :
            this(new DefaultSignerFactory(), new DefaultKeyWrapperFactory(), new DefaultAuthenticatedEncryptorFactory(), new JsonHeaderCache())
        {
            _disposeFactories = true;
        }

        public JsonWebTokenWriter(
            ISignerFactory signerFactory,
            IKeyWrapperFactory keyWrapperFactory,
            IAuthenticatedEncryptorFactory authenticatedEncryptorFactory,
            JsonHeaderCache headerCache = null)
        {
            _signatureFactory = signerFactory ?? throw new ArgumentNullException(nameof(signerFactory));
            _keyWrapFactory = keyWrapperFactory ?? throw new ArgumentNullException(nameof(keyWrapperFactory));
            _authenticatedEncryptionFactory = authenticatedEncryptorFactory ?? throw new ArgumentNullException(nameof(authenticatedEncryptorFactory));
            _headerCache = headerCache ?? new JsonHeaderCache();
        }

        /// <summary>
        /// Gets or sets the token lifetime in minutes.
        /// </summary>
        /// <remarks>Used by <see cref="WriteToken(JwtDescriptor)"/> to set the default expiration ('exp'). <see cref="DefaultTokenLifetimeInMinutes"/> for the default.</remarks>
        /// <exception cref="ArgumentOutOfRangeException">'value' less than 1.</exception>
        public int TokenLifetimeInMinutes
        {
            get
            {
                return _defaultTokenLifetimeInMinutes;
            }

            set
            {
                if (value < 1)
                {
                    Errors.ThrowMustBeGreaterThanZero(nameof(value), value);
                }

                _defaultTokenLifetimeInMinutes = value;
            }
        }

        /// <summary>
        /// Gets or sets a bool that controls if token creation will set default 'exp', 'nbf' and 'iat' if not specified.
        /// </summary>
        /// <remarks>See: <see cref="DefaultTokenLifetimeInMinutes"/>, <see cref="TokenLifetimeInMinutes"/> for defaults and configuration.</remarks>
        public bool SetDefaultTimesOnTokenCreation { get; set; } = false;

        public bool IgnoreTokenValidation { get; set; } = false;

        public bool EnableHeaderCaching
        {
            get => _headerCache != null;
            set
            {
                if (value)
                {
                    if (_headerCache == null)
                    {
                        _headerCache = new JsonHeaderCache();
                    }
                }
                else
                {
                    _headerCache = null;
                }
            }
        }

        public string WriteToken(JwtDescriptor descriptor)
        {
            if (descriptor == null)
            {
                throw new ArgumentNullException(nameof(descriptor));
            }

            if (_disposed)
            {
                Errors.ThrowObjectDisposed(GetType());
            }

            if (descriptor is IJwtPayloadDescriptor claimsDescriptor)
            {
                if (SetDefaultTimesOnTokenCreation && (!claimsDescriptor.ExpirationTime.HasValue || !claimsDescriptor.IssuedAt.HasValue || !claimsDescriptor.NotBefore.HasValue))
                {
                    DateTime now = DateTime.UtcNow;
                    if (!claimsDescriptor.ExpirationTime.HasValue)
                    {
                        claimsDescriptor.ExpirationTime = now + TimeSpan.FromMinutes(TokenLifetimeInMinutes);
                    }

                    if (!claimsDescriptor.IssuedAt.HasValue)
                    {
                        claimsDescriptor.IssuedAt = now;
                    }
                }
            }

            if (descriptor.Algorithm == null)
            {
                descriptor.Algorithm = SignatureAlgorithm.None.Name;
            }

            if (!IgnoreTokenValidation)
            {
                descriptor.Validate();
            }

            var encodingContext = new EncodingContext(_headerCache, _signatureFactory, _keyWrapFactory, _authenticatedEncryptionFactory);
            return descriptor.Encode(encodingContext);
        }

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
