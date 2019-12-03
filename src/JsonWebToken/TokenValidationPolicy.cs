// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using System;
using System.Collections.Generic;

namespace JsonWebToken
{
    /// <summary>
    /// Defines the validations to apply to a JWT.
    /// </summary>
    public sealed class TokenValidationPolicy
    {
        internal const int MissingAudience = 0x01;
        internal const int InvalidAudience = 0x02;
        internal const int Audience = MissingAudience | InvalidAudience;
        internal const int MissingIssuer = 0x04;
        internal const int InvalidIssuer = 0x08;
        internal const int Issuer = MissingIssuer | InvalidIssuer;
        internal const int ExpirationTime = 0x10;
        internal const int ExpirationTimeRequired = 0x20;
        internal const int NotBefore = 0x40;

        /// <summary>
        /// Represents an policy without any validation. Do not use it without consideration.
        /// </summary>
        public static readonly TokenValidationPolicy NoValidation = new TokenValidationPolicyBuilder()
                                                            .IgnoreSignature()
                                                            .IgnoreCriticalHeader()
                                                            .Build();

        private readonly IValidator[] _validators;
        private readonly Dictionary<string, ICriticalHeaderHandler> _criticalHandlers;
        private readonly bool _ignoreCriticalHeader;
        private readonly byte _control;

        internal TokenValidationPolicy(
            IValidator[] validators,
            Dictionary<string, ICriticalHeaderHandler> criticalHandlers,
            int maximumTokenSizeInBytes,
            bool ignoreCriticalHeader,
            SignatureValidationPolicy? signatureValidation,
            byte[] issuer,
            byte[][]? audiences,
            int clockSkrew,
            byte control)
        {
            _validators = validators ?? throw new ArgumentNullException(nameof(validators));
            _criticalHandlers = criticalHandlers ?? throw new ArgumentNullException(nameof(criticalHandlers));
            SignatureValidationPolicy = signatureValidation ?? throw new ArgumentNullException(nameof(signatureValidation));
            _ignoreCriticalHeader = ignoreCriticalHeader;
            MaximumTokenSizeInBytes = maximumTokenSizeInBytes;
            RequiredIssuer = issuer;
            RequiredAudiences = audiences ?? Array.Empty<byte[]>();
            ClockSkrew = clockSkrew;
            _control = control;
        }

        /// <summary>
        /// Gets the maximum token size in bytes.
        /// </summary>
        public int MaximumTokenSizeInBytes { get; }

        /// <summary>
        /// Gets the signature validation parameters.
        /// </summary>
        public SignatureValidationPolicy SignatureValidationPolicy { get; }

        /// <summary>
        /// Gets whether the <see cref="TokenValidationPolicy"/> has validation.
        /// </summary>
        public bool HasValidation => _validators.Length != 0;

        /// <summary>
        /// Gets whether the issuer 'iss' is required.
        /// </summary>
        public bool RequireIssuer => (Control & Issuer) == Issuer;

        /// <summary>
        /// Gets the required issuer.
        /// </summary>
        public byte[] RequiredIssuer { get; }

        /// <summary>
        /// Gets whether the audience 'aud' is required.
        /// </summary>
        public bool RequireAudience => (Control & Audience) == Audience;

        /// <summary>
        /// Gets the required audiences. At least of audience of this list is required.
        /// </summary>
        public byte[][] RequiredAudiences { get; }

        public byte Control => _control;

        /// <summary>
        /// Gets whether the expiration time 'exp' is required.
        /// </summary>
        public bool RequireExpirationTime => (Control & ExpirationTimeRequired) == ExpirationTimeRequired;

        /// <summary>
        /// Defines the clock skrew used for the token lifetime validation.
        /// </summary>
        public int ClockSkrew { get; }

        /// <summary>
        /// Try to validate the token, according to the <paramref name="jwt"/>.
        /// </summary>
        /// <param name="jwt"></param>
        /// <returns></returns>
        public TokenValidationResult TryValidate(Jwt jwt)
        {
            var payload = jwt.Payload!;
            if (payload.Control != 0)
            {
                if (payload.MissingAudience)
                {
                    return TokenValidationResult.MissingClaim(jwt, Claims.AudUtf8);
                }

                if (payload.InvalidAudience)
                {
                    return TokenValidationResult.InvalidClaim(jwt, Claims.AudUtf8);
                }

                if (payload.MissingIssuer)
                {
                    return TokenValidationResult.MissingClaim(jwt, Claims.IssUtf8);
                }

                if (payload.InvalidIssuer)
                {
                    return TokenValidationResult.InvalidClaim(jwt, Claims.IssUtf8);
                }

                if (payload.MissingExpirationTime)
                {
                    return TokenValidationResult.MissingClaim(jwt, Claims.ExpUtf8);
                }

                if (payload.Expired)
                {
                    return TokenValidationResult.Expired(jwt);
                }

                if (payload.NotYetValid)
                {
                    return TokenValidationResult.NotYetValid(jwt);
                }
            }

            var validators = _validators;
            for (int i = 0; i < validators.Length; i++)
            {
                var result = validators[i].TryValidate(jwt);
                if (!result.Succedeed)
                {
                    return result;
                }
            }

            return TokenValidationResult.Success(jwt);
        }

        /// <summary>
        /// Try to validate the token header, according to the <paramref name="header"/>.
        /// </summary>
        /// <param name="header"></param>
        /// <returns></returns>
        public TokenValidationResult TryValidate(JwtHeader header)
        {
            if (_ignoreCriticalHeader)
            {
                goto Success;
            }

            var crit = header.Crit;
            if (crit is null || crit.Count == 0)
            {
                goto Success;
            }

            for (int i = 0; i < crit.Count; i++)
            {
                var criticalHeader = crit[i];
                if (!header.ContainsKey(criticalHeader))
                {
                    return TokenValidationResult.CriticalHeaderMissing(criticalHeader);
                }
                else
                {
                    if (_criticalHandlers.TryGetValue(criticalHeader, out var handler))
                    {
                        if (!handler.TryHandle(header, criticalHeader))
                        {
                            return TokenValidationResult.InvalidHeader(criticalHeader);
                        }
                    }
                    else
                    {
                        return TokenValidationResult.CriticalHeaderUnsupported(criticalHeader);
                    }
                }
            }

        Success:
            return TokenValidationResult.Success();
        }

        /// <summary>
        /// Try to validate the token signature.
        /// </summary>
        /// <param name="jwt"></param>
        /// <param name="contentBytes"></param>
        /// <param name="signatureSegment"></param>
        /// <returns></returns>
        public TokenValidationResult TryValidateSignature(Jwt jwt, ReadOnlySpan<byte> contentBytes, ReadOnlySpan<byte> signatureSegment)
        {
            return SignatureValidationPolicy.TryValidateSignature(jwt, contentBytes, signatureSegment);
        }
    }
}
