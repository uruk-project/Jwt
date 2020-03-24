// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using JsonWebToken.Internal;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace JsonWebToken
{
    /// <summary>
    /// Defines the validations to apply to a JWT.
    /// </summary>
    public sealed class TokenValidationPolicy
    {
        internal const int MissingAudienceFlag = 0x01;
        internal const int InvalidAudienceFlag = 0x02;
        internal const int AudienceFlag = MissingAudienceFlag | InvalidAudienceFlag;
        internal const int MissingIssuerFlag = 0x04;
        internal const int InvalidIssuerFlag = 0x08;
        internal const int IssuerFlag = MissingIssuerFlag | InvalidIssuerFlag;
        internal const int ExpirationTimeFlag = 0x10;
        internal const int ExpirationTimeRequiredFlag = 0x20;
        internal const int NotBeforeFlag = 0x40;

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
            bool ignoreNestedToken,
            SignatureValidationPolicy? signatureValidation,
            byte[]? issuer,
            byte[][] audiences,
            int clockSkew,
            byte control)
        {
            _validators = validators ?? throw new ArgumentNullException(nameof(validators));
            _criticalHandlers = criticalHandlers ?? throw new ArgumentNullException(nameof(criticalHandlers));
            SignatureValidationPolicy = signatureValidation ?? throw new ArgumentNullException(nameof(signatureValidation));
            _ignoreCriticalHeader = ignoreCriticalHeader;
            IgnoreNestedToken = ignoreNestedToken;
            MaximumTokenSizeInBytes = maximumTokenSizeInBytes;
            ClockSkew = clockSkew;
            _control = control;
            RequiredAudiencesBinary = audiences;
            RequiredAudiences = audiences.Select(a => Encoding.UTF8.GetString(a)).ToArray();

            if (issuer != null)
            {
                RequiredIssuerBinary = issuer;
                RequiredIssuer = Encoding.UTF8.GetString(issuer);
            }
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
        public bool RequireIssuer => (ValidationControl & IssuerFlag) == IssuerFlag;

        /// <summary>
        /// Gets the required issuer, in UTF8 binary format.
        /// </summary>
        internal byte[]? RequiredIssuerBinary { get; }

        /// <summary>
        /// Gets the required issuer.
        /// </summary>
        public string? RequiredIssuer { get; }

        /// <summary>
        /// Gets whether the audience 'aud' is required.
        /// </summary>
        public bool RequireAudience => (ValidationControl & AudienceFlag) == AudienceFlag;

        /// <summary>
        /// Gets the required audience array, in UTF8 binary format. At least one audience of this list is required.
        /// </summary>
        public byte[][] RequiredAudiencesBinary { get; }

        /// <summary>
        /// Gets the required issuer.
        /// </summary>
        public string[] RequiredAudiences { get; }

        /// <summary>
        /// Gets the validation control bits.
        /// </summary>
        public byte ValidationControl => _control;

        /// <summary>
        /// Gets whether the expiration time 'exp' is required.
        /// </summary>
        public bool RequireExpirationTime => (ValidationControl & ExpirationTimeRequiredFlag) == ExpirationTimeRequiredFlag;

        /// <summary>
        /// Defines the clock skrew used for the token lifetime validation.
        /// </summary>
        public int ClockSkew { get; }

        /// <summary>
        /// Gets the extension points used to handle the critical headers.
        /// </summary>
        public Dictionary<string, ICriticalHeaderHandler> CriticalHandlers => _criticalHandlers;

        /// <summary>
        /// Ignores the nested token reading and validation. 
        /// </summary>
        public bool IgnoreNestedToken { get; }

        /// <summary>
        /// Try to validate the token, according to the <paramref name="jwt"/>.
        /// </summary>
        /// <param name="jwt"></param>
        /// <returns></returns>
        public TokenValidationResult TryValidateJwt(Jwt jwt)
        {
            var payload = jwt.Payload!;
            if (payload.ValidationControl != 0)
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
        public TokenValidationResult TryValidateHeader(JwtHeader header)
        {
            if (!_ignoreCriticalHeader)
            {
                var handlers = header.CriticalHeaderHandlers;
                if (handlers != null)
                {
                    for (int i = 0; i < handlers.Count; i++)
                    {
                        KeyValuePair<string, ICriticalHeaderHandler> handler = handlers[i];
                        if (handler.Value is null)
                        {
                            return TokenValidationResult.CriticalHeaderUnsupported(handler.Key);
                        }

                        if (!handler.Value.TryHandle(header, handler.Key))
                        {
                            return TokenValidationResult.InvalidHeader(handler.Key);
                        }
                    }
                }
            }

            return TokenValidationResult.Success();
        }

        /// <summary>
        /// Try to validate the token signature.
        /// </summary>
        /// <param name="header"></param>
        /// <param name="contentBytes"></param>
        /// <param name="signatureSegment"></param>
        /// <returns></returns>
        public SignatureValidationResult TryValidateSignature(JwtHeader header, ReadOnlySpan<byte> contentBytes, ReadOnlySpan<byte> signatureSegment)
        {
            return SignatureValidationPolicy.TryValidateSignature(header, contentBytes, signatureSegment);
        }
    }
}
