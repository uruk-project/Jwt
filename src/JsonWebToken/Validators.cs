using System;
using System.Collections.Generic;

namespace JsonWebToken
{
    public static class Validators
    {
        /// <summary>
        /// Determines if the audiences found in a <see cref="JsonWebToken"/> are valid.
        /// </summary>
        /// <param name="audiences">The audiences found in the <see cref="JsonWebToken"/>.</param>
        /// <param name="jwtToken">The <see cref="JsonWebToken"/> being validated.</param>
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>
        /// <remarks>An EXACT match is required.</remarks>
        public static TokenValidationResult ValidateAudience(IEnumerable<string> audiences, JsonWebToken jwtToken, TokenValidationParameters validationParameters)
        {
            if (validationParameters == null)
            {
                throw new ArgumentNullException(nameof(validationParameters));
            }

            if (audiences == null)
            {
                throw new ArgumentNullException(nameof(audiences));
            }

            if (!validationParameters.ValidateAudience)
            {
                return TokenValidationResult.Success(jwtToken);
            }

            bool missingAudience = true;
            foreach (string audience in audiences)
            {
                missingAudience = false;
                if (string.IsNullOrWhiteSpace(audience))
                {
                    continue;
                }

                if (validationParameters.ValidAudiences != null)
                {
                    foreach (string validAudience in validationParameters.ValidAudiences)
                    {
                        if (string.Equals(audience, validAudience, StringComparison.Ordinal))
                        {
                            return TokenValidationResult.Success(jwtToken);
                        }
                    }
                }

                if (!string.IsNullOrWhiteSpace(validationParameters.ValidAudience))
                {
                    if (string.Equals(audience, validationParameters.ValidAudience, StringComparison.Ordinal))
                    {
                        return TokenValidationResult.Success(jwtToken);
                    }
                }
            }

            if (missingAudience)
            {
                return TokenValidationResult.MissingAudience(jwtToken);
            }

            return TokenValidationResult.InvalidAudience(jwtToken);
        }

        /// <summary>
        /// Determines if an issuer found in a <see cref="JsonWebToken"/> is valid.
        /// </summary>
        /// <param name="issuer">The issuer to validate</param>
        /// <param name="jwtToken">The <see cref="JsonWebToken"/> that is being validated.</param>
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>        
        /// <remarks>An EXACT match is required.</remarks>
        public static TokenValidationResult ValidateIssuer(string issuer, JsonWebToken jwtToken, TokenValidationParameters validationParameters)
        {
            if (validationParameters == null)
            {
                throw new ArgumentNullException(nameof(validationParameters));
            }

            if (!validationParameters.ValidateIssuer)
            {
                return TokenValidationResult.Success(jwtToken);
            }

            if (string.IsNullOrWhiteSpace(issuer))
            {
                return TokenValidationResult.MissingIssuer(jwtToken);
            }

            if (string.Equals(validationParameters.ValidIssuer, issuer, StringComparison.Ordinal))
            {
                return TokenValidationResult.Success(jwtToken);
            }

            return TokenValidationResult.InvalidIssuer(jwtToken);
        }

        /// <summary>
        /// Validates the lifetime of a <see cref="JsonWebToken"/>.
        /// </summary>
        /// <param name="notBefore">The 'notBefore' time found in the <see cref="JsonWebToken"/>.</param>
        /// <param name="expires">The 'expiration' time found in the <see cref="JsonWebToken"/>.</param>
        /// <param name="jwtToken">The <see cref="JsonWebToken"/> being validated.</param>
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>
        /// <remarks>All time comparisons apply <see cref="TokenValidationParameters.ClockSkew"/>.</remarks>
        public static TokenValidationResult ValidateLifetime(int? notBefore, int? expires, JsonWebToken jwtToken, TokenValidationParameters validationParameters)
        {
            if (validationParameters == null)
            {
                throw new ArgumentNullException(nameof(validationParameters));
            }

            if (!validationParameters.ValidateLifetime)
            {
                return TokenValidationResult.Success(jwtToken);
            }

            if (!expires.HasValue && validationParameters.RequireExpirationTime)
            {
                return TokenValidationResult.NoExpiration(jwtToken);
            }

            if (notBefore.HasValue && expires.HasValue && (notBefore.Value > expires.Value))
            {
                return TokenValidationResult.InvalidLifetime(jwtToken);
            }

            var utcNow = EpochTime.GetIntDate(DateTime.UtcNow);
            if (notBefore.HasValue && (notBefore.Value > DateTimeUtil.Add(utcNow, validationParameters.ClockSkew)))
            {
                return TokenValidationResult.NotYetValid(jwtToken);
            }

            if (expires.HasValue && (expires.Value < DateTimeUtil.Add(utcNow, -validationParameters.ClockSkew)))
            {
                return TokenValidationResult.Expired(jwtToken);
            }

            return TokenValidationResult.Success(jwtToken);
        }

        /// <summary>
        /// Validates if a token has been replayed.
        /// </summary>
        /// <param name="expirationTime">When does the security token expire.</param>
        /// <param name="jwtToken">The <see cref="JsonWebToken"/> being validated.</param>
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>
        public static TokenValidationResult ValidateTokenReplay(int? expirationTime, JsonWebToken jwtToken, TokenValidationParameters validationParameters, ITokenReplayCache tokenReplayCache)
        {
            if (jwtToken == null)
            {
                throw new ArgumentNullException(nameof(jwtToken));
            }

            if (validationParameters == null)
            {
                throw new ArgumentNullException(nameof(validationParameters));
            }

            // check if token if replay cache is set, then there must be an expiration time.
            if (validationParameters.ValidateTokenReplay && tokenReplayCache != null)
            {
                if (!expirationTime.HasValue)
                {
                    return TokenValidationResult.NoExpiration(jwtToken);
                }

                if (!tokenReplayCache.TryAdd(jwtToken, EpochTime.ToDateTime(expirationTime.Value)))
                {
                    return TokenValidationResult.TokenReplayed(jwtToken);
                }
            }

            // if it reaches here, that means no token replay is detected.
            return TokenValidationResult.Success(jwtToken);
        }
    }
}
