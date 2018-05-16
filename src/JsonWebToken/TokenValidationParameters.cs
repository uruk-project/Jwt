using System;
using System.Collections.Generic;
using System.Linq;

namespace JsonWebToken
{
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
