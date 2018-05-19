using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace JsonWebToken
{
    public class ValidationBuilder
    {
        public const int DefaultMaximumTokenSizeInBytes = 1024 * 1024 * 2; // 2meg.

        private readonly IList<IValidation> _validations = new List<IValidation>();
        private int _maximumTokenSizeInBytes = DefaultMaximumTokenSizeInBytes;

        public static ValidationParameters NoValidation = new ValidationBuilder().Build();

        public ValidationBuilder AddDefaultValidation(IEnumerable<IKeyProvider> keyProviders, string issuer, IEnumerable<string> audiences)
        {
            AddSignatureValidation(keyProviders);
            AddLifetimeValidation();
            AddIssuerValidation(issuer);
            AddAudienceValidation(audiences);
            return this;
        }

        public ValidationBuilder MaximumTokenSizeInBytes(int bytes)
        {
            if (bytes <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(bytes), ErrorMessages.FormatInvariant(ErrorMessages.MustBeGreaterThanZero, nameof(MaximumTokenSizeInBytes), bytes));
            }

            _maximumTokenSizeInBytes = bytes;
            return this;
        }

        public ValidationBuilder AddSignatureValidation(IKeyProvider keyProvider)
        {
            _validations.Add(new SignatureValidation(keyProvider));
            return this;
        }

        public ValidationBuilder AddSignatureValidation(JsonWebKey key)
        {
            return AddSignatureValidation(new JsonWebKeySet(key));
        }

        public ValidationBuilder AddSignatureValidation(JsonWebKeySet keySet)
        {
            return AddSignatureValidation(new StaticKeyProvider(keySet));
        }

        public ValidationBuilder AddSignatureValidation(IEnumerable<IKeyProvider> keyProviders)
        {
            foreach (var keyProvider in keyProviders)
            {
                AddSignatureValidation(keyProvider);
            }

            return this;
        }

        public ValidationBuilder AddLifetimeValidation(bool requireExpirationTime = true, int clockSkew = 300)
        {
            if (clockSkew <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(clockSkew), ErrorMessages.FormatInvariant(ErrorMessages.MustBeGreaterThanTimeSpanZero, nameof(clockSkew), clockSkew));
            }

            _validations.Add(new LifetimeValidation { RequireExpirationTime = requireExpirationTime, ClockSkew = clockSkew });
            return this;
        }

        public ValidationBuilder AddAudienceValidation(string audience)
        {
            if (string.IsNullOrEmpty(audience))
            {
                throw new ArgumentNullException(nameof(audience));
            }

            _validations.Add(new AudienceValidation(new[] { audience }));
            return this;
        }

        public ValidationBuilder AddAudienceValidation(IEnumerable<string> audiences)
        {
            if (audiences == null)
            {
                throw new ArgumentNullException(nameof(audiences));
            }

            _validations.Add(new AudienceValidation(audiences));
            return this;
        }

        public ValidationBuilder AddIssuerValidation(string issuer)
        {
            if (string.IsNullOrEmpty(issuer))
            {
                throw new ArgumentNullException(nameof(issuer));
            }

            _validations.Add(new IssuerValidation(issuer));
            return this;
        }

        public ValidationBuilder AddTokenReplayValidation(ITokenReplayCache tokenReplayCache)
        {
            if (tokenReplayCache == null)
            {
                throw new ArgumentNullException(nameof(tokenReplayCache));
            }

            _validations.Add(new TokenReplayValidation(tokenReplayCache));
            return this;
        }

        public ValidationParameters Build()
        {
            var parameters = new ValidationParameters(_validations);
            parameters.MaximumTokenSizeInBytes = _maximumTokenSizeInBytes;
            return parameters;
        }
    }

    public interface IValidation
    {
        TokenValidationResult TryValidate(JsonWebToken jwt);
    }

    public class TokenReplayValidation : IValidation
    {
        private readonly ITokenReplayCache _tokenReplayCache;

        public TokenReplayValidation(ITokenReplayCache tokenReplayCache)
        {
            _tokenReplayCache = tokenReplayCache ?? throw new ArgumentNullException(nameof(tokenReplayCache));
        }

        public TokenValidationResult TryValidate(JsonWebToken jwt)
        {
            if (jwt == null)
            {
                throw new ArgumentNullException(nameof(jwt));
            }

            // check if token if replay cache is set, then there must be an expiration time.
            var expires = jwt.Expires;
            if (!expires.HasValue)
            {
                return TokenValidationResult.NoExpiration(jwt);
            }

            if (!_tokenReplayCache.TryAdd(jwt, expires.Value))
            {
                return TokenValidationResult.TokenReplayed(jwt);
            }

            return TokenValidationResult.Success(jwt);
        }
    }

    public class IssuerValidation : IValidation
    {
        private readonly string _issuer;

        public IssuerValidation(string issuer)
        {
            _issuer = issuer;
        }

        public TokenValidationResult TryValidate(JsonWebToken jwt)
        {
            var issuer = jwt.Issuer;
            if (string.IsNullOrWhiteSpace(issuer))
            {
                return TokenValidationResult.MissingIssuer(jwt);
            }

            if (string.Equals(_issuer, issuer, StringComparison.Ordinal))
            {
                return TokenValidationResult.Success(jwt);
            }

            return TokenValidationResult.InvalidIssuer(jwt);
        }
    }

    public class AudienceValidation : IValidation
    {
        private readonly IEnumerable<string> _audiences;

        public AudienceValidation(IEnumerable<string> audiences)
        {
            _audiences = audiences;
        }

        public TokenValidationResult TryValidate(JsonWebToken jwt)
        {
            bool missingAudience = true;
            foreach (string audience in jwt.Audiences)
            {
                missingAudience = false;
                if (string.IsNullOrWhiteSpace(audience))
                {
                    continue;
                }

                foreach (string validAudience in _audiences)
                {
                    if (string.Equals(audience, validAudience, StringComparison.Ordinal))
                    {
                        return TokenValidationResult.Success(jwt);
                    }
                }
            }

            if (missingAudience)
            {
                return TokenValidationResult.MissingAudience(jwt);
            }

            return TokenValidationResult.InvalidAudience(jwt);
        }
    }

    public class LifetimeValidation : IValidation
    {
        public int ClockSkew { get; set; }

        public bool RequireExpirationTime { get; set; }

        public TokenValidationResult TryValidate(JsonWebToken jwt)
        {
            var expires = jwt.Payload.Exp;

            if (!expires.HasValue && RequireExpirationTime)
            {
                return TokenValidationResult.NoExpiration(jwt);
            }

            var notBefore = jwt.Payload.Nbf;
            if (notBefore.HasValue && expires.HasValue && (notBefore.Value > expires.Value))
            {
                return TokenValidationResult.InvalidLifetime(jwt);
            }

            var utcNow = EpochTime.GetIntDate(DateTime.UtcNow);
            if (notBefore.HasValue && (notBefore.Value > DateTimeUtil.Add(utcNow, ClockSkew)))
            {
                return TokenValidationResult.NotYetValid(jwt);
            }

            if (expires.HasValue && (expires.Value < DateTimeUtil.Add(utcNow, -ClockSkew)))
            {
                return TokenValidationResult.Expired(jwt);
            }

            return TokenValidationResult.Success(jwt);
        }
    }

    public class SignatureValidation : IValidation
    {
        private readonly IKeyProvider _keyProvider;

        public SignatureValidation(IKeyProvider keyProvider)
        {
            _keyProvider = keyProvider;
        }

        public TokenValidationResult TryValidate(JsonWebToken jwt)
        {
            if (jwt == null)
            {
                throw new ArgumentNullException(nameof(jwt));
            }

            if (!jwt.HasSignature)
            {
                return TokenValidationResult.MissingSignature(jwt);
            }

            bool keysTried = false;
            ReadOnlySpan<byte> signatureBytes;
            try
            {
                signatureBytes = jwt.GetSignatureBytes();
            }
            catch (FormatException)
            {
                return TokenValidationResult.MalformedSignature(jwt);
            }

            int length = jwt.Separators[0] + jwt.Separators[1];
            unsafe
            {
#if NETCOREAPP2_1
                Span<byte> encodedBytes = stackalloc byte[length];
                Encoding.UTF8.GetBytes(jwt.RawData.AsSpan().Slice(0, length), encodedBytes);
#else
                var encodedBytes = Encoding.UTF8.GetBytes(jwt.RawData.Substring(0, length));
#endif
                var keys = ResolveSigningKey(jwt);
                foreach (var key in keys)
                {
                    try
                    {
                        if (TryValidateSignature(encodedBytes, signatureBytes, key, jwt.Header.Alg))
                        {
                            jwt.Header.SigningKey = key;
                            return TokenValidationResult.Success(jwt);
                        }
                    }
                    catch
                    {
                        // swallow exception
                    }

                    keysTried = true;
                }
            }

            if (keysTried)
            {
                return TokenValidationResult.InvalidSignature(jwt);
            }

            return TokenValidationResult.KeyNotFound(jwt);
        }

        private bool TryValidateSignature(ReadOnlySpan<byte> encodedBytes, ReadOnlySpan<byte> signature, JsonWebKey key, string algorithm)
        {
            var signatureProvider = key.CreateSignatureProvider(algorithm, false);
            if (signatureProvider == null)
            {
                return false;
            }

            try
            {
#if NETCOREAPP2_1
                return signatureProvider.Verify(encodedBytes, signature);
#else
                return signatureProvider.Verify(encodedBytes, signature);
#endif
            }
            finally
            {
                key.ReleaseSignatureProvider(signatureProvider);
            }
        }

        private IEnumerable<JsonWebKey> ResolveSigningKey(JsonWebToken jwtToken)
        {
            var keys = new List<JsonWebKey>();
            var keySet = _keyProvider.GetKeys(jwtToken);
            if (keySet != null)
            {
                for (int j = 0; j < keySet.Keys.Count; j++)
                {
                    var key = keySet.Keys[j];
                    if ((string.IsNullOrWhiteSpace(key.Use) || string.Equals(key.Use, JsonWebKeyUseNames.Sig, StringComparison.Ordinal)) &&
                         (string.Equals(key.Kid, jwtToken.Header.Kid, StringComparison.Ordinal)))
                    {
                        keys.Add(key);
                    }
                }
            }

            return keys;
        }
    }


    public class ValidationParameters
    {
        private readonly IList<IValidation> _rules;

        public ValidationParameters(IList<IValidation> rules)
        {
            _rules = rules;
        }

        public int MaximumTokenSizeInBytes { get; internal set; }

        public TokenValidationResult TryValidate(JsonWebToken jwt)
        {
            for (int i = 0; i < _rules.Count; i++)
            {
                var result = _rules[i].TryValidate(jwt);
                if (!result.Succedeed)
                {
                    return result;
                }
            }

            return TokenValidationResult.Success(jwt);
        }
    }

    /// <summary>
    /// <summary>
    /// Contains a set of parameters that are used by a <see cref="SecurityTokenHandler"/> when validating a <see cref="SecurityToken"/>.
    /// </summary>
    public class TokenValidationParameters
    {
        private static readonly string[] EmptyString = new string[0];

        public static readonly TokenValidationParameters None = new TokenValidationParameters();

        private int _clockSkew = DefaultClockSkew;
        private int _maximumTokenSizeInBytes = TokenValidationParameters.DefaultMaximumTokenSizeInBytes;
        private IList<string> _validAudiences;

        /// <summary>
        /// Default for the clock skew.
        /// </summary>
        /// <remarks>300 seconds (5 minutes).</remarks>
        public const int DefaultClockSkew = 300; // 5 min.

        /// <summary>
        /// Default for the maximum token size.
        /// </summary>
        /// <remarks>2 MB (mega bytes).</remarks>
        public const Int32 DefaultMaximumTokenSizeInBytes = 1024 * 1024 * 2; // 2meg.

        /// <summary>
        /// Copy constructor for <see cref="TokenValidationParameters"/>.
        /// </summary>
        protected TokenValidationParameters(TokenValidationParameters other)
        {
            if (other == null)
            {
                throw new ArgumentNullException(nameof(other));
            }

            ClockSkew = other.ClockSkew;
            RequireExpirationTime = other.RequireExpirationTime;
            RequireSignedTokens = other.RequireSignedTokens;
            ValidateAudience = other.ValidateAudience;
            ValidateIssuer = other.ValidateIssuer;
            ValidateLifetime = other.ValidateLifetime;
            ValidateTokenReplay = other.ValidateTokenReplay;
            ValidAudience = other.ValidAudience;
            ValidAudiences = other.ValidAudiences;
            ValidIssuer = other.ValidIssuer;
            MaximumTokenSizeInBytes = other.MaximumTokenSizeInBytes;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="TokenValidationParameters"/> class.
        /// </summary>        
        public TokenValidationParameters()
        {
            RequireExpirationTime = true;
            RequireSignedTokens = true;
            ValidateAudience = true;
            ValidateIssuer = true;
            ValidateLifetime = true;
            ValidateTokenReplay = false;
        }

        /// <summary>
        /// Gets or sets the clock skew in seconds to apply when validating a time.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">If 'value' is less than 0.</exception>
        public int ClockSkew
        {
            get
            {
                return _clockSkew;
            }

            set
            {
                if (value < 0)
                {
                    throw new ArgumentOutOfRangeException(nameof(value), ErrorMessages.FormatInvariant(ErrorMessages.MustBeGreaterThanTimeSpanZero, nameof(ClockSkew), value));
                }

                _clockSkew = value;
            }
        }

        /// <summary>
        /// Returns a new instance of <see cref="TokenValidationParameters"/> with values copied from this object.
        /// </summary>
        /// <returns>A new <see cref="TokenValidationParameters"/> object copied from this object</returns>
        public TokenValidationParameters Clone()
        {
            return new TokenValidationParameters(this);
        }

        /// <summary>
        /// Gets or sets a value indicating whether tokens must have an 'expiration' value.
        /// </summary>
        public bool RequireExpirationTime { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether a <see cref="SecurityToken"/> can be considered valid if not signed.
        /// </summary>
        public bool RequireSignedTokens { get; set; } = true;

        /// <summary>
        /// Gets or sets a boolean to control if the audience will be validated during token validation.
        /// </summary>
        public bool ValidateAudience { get; set; }

        /// <summary>
        /// Gets or sets a boolean to control if the issuer will be validated during token validation.
        /// </summary>
        public bool ValidateIssuer { get; set; }

        /// <summary>
        /// Gets or sets a boolean to control if the lifetime will be validated during token validation.
        /// </summary>                
        public bool ValidateLifetime { get; set; }

        /// <summary>
        /// Gets or sets a boolean to control if the token replay will be validated during token validation.
        /// </summary>                
        public bool ValidateTokenReplay { get; set; }

        /// <summary>
        /// Gets or sets a string that represents a valid audience that will be used to check against the token's audience.
        /// </summary>
        public string ValidAudience
        {
            get => _validAudiences.Count > 0 ? _validAudiences[0] : null;
            set
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    _validAudiences = EmptyString;
                }
                else
                {
                    _validAudiences = new[] { value };
                }
            }
        }

        /// <summary>
        /// Gets or sets the <see cref="IEnumerable{string}"/> that contains valid audiences that will be used to check against the token's audience.
        /// </summary>
        public ICollection<string> ValidAudiences
        {
            get => _validAudiences;
            set
            {
                if (value == null)
                {
                    _validAudiences = EmptyString;
                }
                else
                {
                    _validAudiences = value.ToList();
                }
            }
        }

        /// <summary>
        /// Gets or sets a <see cref="string"/> that represents a valid issuer that will be used to check against the token's issuer.
        /// </summary>
        public string ValidIssuer { get; set; }

        /// <summary>
        /// Gets and sets the maximum token size in bytes that will be processed.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">'value' less than 1.</exception>
        public int MaximumTokenSizeInBytes
        {
            get { return _maximumTokenSizeInBytes; }
            set
            {
                if (value <= 0)
                {
                    throw new ArgumentOutOfRangeException(nameof(value), ErrorMessages.FormatInvariant(ErrorMessages.MustBeGreaterThanZero, nameof(MaximumTokenSizeInBytes), value));
                }

                _maximumTokenSizeInBytes = value;
            }
        }

        public void ThrowIfInvalid()
        {
            if (ValidateIssuer && string.IsNullOrWhiteSpace(ValidIssuer))
            {
                throw new ArgumentException(ErrorMessages.FormatInvariant(ErrorMessages.MustNoBeNullIfRequired, nameof(ValidIssuer), ValidateIssuer, nameof(ValidIssuer)));
            }


            if (ValidateAudience && ValidAudiences.Count == 0)
            {
                throw new ArgumentException(ErrorMessages.FormatInvariant(ErrorMessages.MustNoBeNullIfRequired, nameof(ValidAudience), ValidateAudience, nameof(ValidAudiences)));
            }
        }
    }
}
