using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Buffers;
using System.Text;

namespace JsonWebToken
{
    /// <summary>
    /// See: http://tools.ietf.org/html/rfc7519 and http://www.rfc-editor.org/info/rfc7515
    /// </summary>
    public class JsonWebTokenWriter
    {
        private int _defaultTokenLifetimeInMinutes = DefaultTokenLifetimeInMinutes;

        private static readonly byte dot = Convert.ToByte('.');

        /// <summary>
        /// Default lifetime of tokens created. When creating tokens, if 'expires' and 'notbefore' are both null, then a default will be set to: expires = DateTime.UtcNow, notbefore = DateTime.UtcNow + TimeSpan.FromMinutes(TokenLifetimeInMinutes).
        /// </summary>
        public static readonly int DefaultTokenLifetimeInMinutes = 60;

        /// <summary>
        /// Gets or sets the token lifetime in minutes.
        /// </summary>
        /// <remarks>Used by <see cref="CreateToken(JsonWebTokenDescriptor)"/> to set the default expiration ('exp'). <see cref="DefaultTokenLifetimeInMinutes"/> for the default.</remarks>
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
                    throw new ArgumentOutOfRangeException(nameof(value), ErrorMessages.FormatInvariant(ErrorMessages.MustBeGreaterThanZero, nameof(TokenLifetimeInMinutes), value));
                }

                _defaultTokenLifetimeInMinutes = value;
            }
        }

        /// <summary>
        /// Gets or sets a bool that controls if token creation will set default 'exp', 'nbf' and 'iat' if not specified.
        /// </summary>
        /// <remarks>See: <see cref="DefaultTokenLifetimeInMinutes"/>, <see cref="TokenLifetimeInMinutes"/> for defaults and configuration.</remarks>
        public bool SetDefaultTimesOnTokenCreation { get; set; } = false;

        public string WriteToken(JwtDescriptor descriptor)
        {
            if (descriptor == null)
            {
                throw new ArgumentNullException(nameof(descriptor));
            }

            var claimsDescriptor = descriptor as IJwtPayloadDescriptor;
            if (claimsDescriptor != null)
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

                    if (!claimsDescriptor.NotBefore.HasValue)
                    {
                        claimsDescriptor.NotBefore = now;
                    }
                }
            }

            return descriptor.Encode();
        }
    }
}
