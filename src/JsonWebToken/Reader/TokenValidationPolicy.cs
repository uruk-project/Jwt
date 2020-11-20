// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;

namespace JsonWebToken
{
    /// <summary>
    /// Defines the validations to apply to a JWT.
    /// </summary>
    public sealed class TokenValidationPolicy
    {
        internal const byte MissingAudienceMask = 0x01;
        internal const byte InvalidAudienceMask = 0x02;
        internal const byte AudienceMask = MissingAudienceMask | InvalidAudienceMask;
        internal const byte MissingIssuerMask = 0x04;
        internal const byte InvalidIssuerMask = 0x08;
        internal const byte IssuerMask = MissingIssuerMask | InvalidIssuerMask;
        internal const byte ExpirationTimeMask = 0x10;
        internal const byte ExpirationTimeRequiredMask = 0x20;
        internal const byte NotBeforeMask = 0x40;

        private static readonly IJwtHeaderDocumentCache _disabledJwtHeaderCache = new DisabledJwtHeaderDocumentCache();

        /// <summary>Represents an policy without any validation. Do not use it without consideration.</summary>
        public static readonly TokenValidationPolicy NoValidation = new TokenValidationPolicyBuilder()
                                                            .IgnoreSignatureByDefault()
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
            bool headerCacheDisabled,
            SignatureValidationPolicy? signaturePolicy,
            IKeyProvider[]? encryptionKeyProviders,
            byte[][] issuers,
            byte[][] audiences,
            int clockSkew,
            byte control)
        {
            _validators = validators ?? throw new ArgumentNullException(nameof(validators));
            _criticalHandlers = criticalHandlers ?? throw new ArgumentNullException(nameof(criticalHandlers));
            SignatureValidationPolicy = signaturePolicy ?? throw new ArgumentNullException(nameof(signaturePolicy));
            DecryptionKeyProviders = encryptionKeyProviders ?? Array.Empty<IKeyProvider>();
            _ignoreCriticalHeader = ignoreCriticalHeader;
            IgnoreNestedToken = ignoreNestedToken;
            MaximumTokenSizeInBytes = maximumTokenSizeInBytes;
            ClockSkew = clockSkew;
            _control = control;
            RequiredAudiencesBinary = audiences;
            RequiredAudiences = audiences.Select(a => Utf8.GetString(a)).ToArray();
            RequiredIssuersBinary = issuers;
            RequiredIssuers = issuers.Select(i => Utf8.GetString(i)).ToArray();
            HeaderCache = headerCacheDisabled ? _disabledJwtHeaderCache : new LruJwtHeaderDocumentCache();
        }

        /// <summary>Gets the maximum token size in bytes.</summary>
        public int MaximumTokenSizeInBytes { get; }

        /// <summary>Gets the signature validation parameters.</summary>
        public SignatureValidationPolicy SignatureValidationPolicy { get; }

        /// <summary>Gets whether the <see cref="TokenValidationPolicy"/> has validation.</summary>
        public bool HasValidation => _control != 0 || _validators.Length != 0 || SignatureValidationPolicy.IsEnabled;

        /// <summary>Gets whether the issuer 'iss' is required.</summary>
        public bool RequireIssuer => (_control & IssuerMask) == IssuerMask;

        /// <summary>Gets the required issuers, in UTF8 binary format. At least one issuer of this list is required.</summary>
        public byte[][] RequiredIssuersBinary { get; }

        /// <summary>Gets the required issuers.</summary>
        public string[] RequiredIssuers { get; }

        /// <summary>Gets whether the audience 'aud' is required.</summary>
        public bool RequireAudience => (_control & AudienceMask) == AudienceMask;

        /// <summary>Gets the required audience array, in UTF8 binary format. At least one audience of this list is required.</summary>
        internal byte[][] RequiredAudiencesBinary { get; }

        /// <summary>Gets the required issuer.</summary>
        public string[] RequiredAudiences { get; }

        /// <summary>Gets the validation control bits.</summary>
        public byte Control => _control;

        /// <summary>Gets whether the expiration time 'exp' is required.</summary>
        public bool RequireExpirationTime => (_control & ExpirationTimeRequiredMask) == ExpirationTimeRequiredMask;

        /// <summary>Defines the clock skrew used for the token lifetime validation.</summary>
        public int ClockSkew { get; }

        /// <summary>Gets the extension points used to handle the critical headers.</summary>
        public Dictionary<string, ICriticalHeaderHandler> CriticalHandlers => _criticalHandlers;

        /// <summary>Ignores the nested token reading and validation. </summary>
        public bool IgnoreNestedToken { get; }

        /// <summary>Gets whether the critical headers should be ignored.</summary>
        public bool IgnoreCriticalHeader => _ignoreCriticalHeader;

        /// <summary>Gets the <see cref="IJwtHeaderDocumentCache"/>.</summary>
        public IJwtHeaderDocumentCache HeaderCache { get; }

        /// <summary>Gets the array of <see cref="IKeyProvider"/> used for decryption.</summary>
        public IKeyProvider[] DecryptionKeyProviders { get; }

        /// <summary>Try to validate the token, according to the <paramref name="header"/> and the <paramref name="payload"/>.</summary>
        /// <param name="header"></param>
        /// <param name="payload"></param>
        /// <param name="error"></param>
        public bool TryValidateJwt(JwtHeaderDocument header, JwtPayloadDocument payload, [NotNullWhen(false)] out TokenValidationError? error)
        {
            if (payload.Control != 0)
            {
                if (RequireAudience)
                {
                    if (payload.MissingAudience)
                    {
                        error = TokenValidationError.MissingClaim(JwtClaimNames.Aud.ToString());
                        goto Error;
                    }

                    if (payload.InvalidAudience)
                    {
                        error = TokenValidationError.InvalidClaim(JwtClaimNames.Aud.ToString());
                        goto Error;
                    }
                }

                if (RequireIssuer)
                {
                    if (payload.MissingIssuer)
                    {
                        error = TokenValidationError.MissingClaim(JwtClaimNames.Iss.ToString());
                        goto Error;
                    }

                    if (payload.InvalidIssuer)
                    {
                        error = TokenValidationError.InvalidClaim(JwtClaimNames.Iss.ToString());
                        goto Error;
                    }
                }

                if (RequireExpirationTime)
                {
                    if (payload.MissingExpirationTime)
                    {
                        error = TokenValidationError.MissingClaim(JwtClaimNames.Exp.ToString());
                        goto Error;
                    }

                    if (payload.Expired)
                    {
                        error = TokenValidationError.Expired();
                        goto Error;
                    }
                }

                if (payload.NotYetValid)
                {
                    error = TokenValidationError.NotYetValid();
                    goto Error;
                }
            }

            var validators = _validators;
            for (int i = 0; i < validators.Length; i++)
            {
                if (!validators[i].TryValidate(header, payload, out error))
                {
                    goto Error;
                }
            }

            error = null;
            return true;

        Error:
            return false;
        }

        /// <summary>Try to validate the token header, according to the <paramref name="header"/>.</summary>
        /// <param name="header"></param>
        /// <param name="error"></param>
        /// <returns><c>true</c> if the <paramref name="header"/> is valid. <c>false</c> otherwise.</returns>
        public bool TryValidateHeader(JwtHeaderDocument header, [NotNullWhen(false)] out TokenValidationError? error)
        {
            if (!IgnoreCriticalHeader)
            {
                if (header.TryGetHeaderParameter(JwtHeaderParameterNames.CritUtf8, out var crit))
                {
                    var handlers = CriticalHandlers;
                    foreach (var critHeader in crit.EnumerateArray<string>())
                    {
                        var critHeaderName = critHeader.GetString()!;
                        if (!handlers.TryGetValue(critHeaderName, out var handler))
                        {
                            error = TokenValidationError.CriticalHeaderUnsupported(critHeaderName);
                            goto Error;
                        }


                        if (!handler.TryHandle(header, critHeaderName))
                        {
                            error = TokenValidationError.InvalidHeader(critHeaderName);
                            goto Error;
                        }
                    }
                }
            }

            error = null;
            return true;

        Error:
            return false;
        }

        /// <summary>Try to validate the token signature.</summary>
        /// <param name="header"></param>
        /// <param name="payload"></param>
        /// <param name="contentBytes"></param>
        /// <param name="signatureSegment"></param>
        /// <returns></returns>
        public SignatureValidationResult TryValidateSignature(JwtHeaderDocument header, JwtPayloadDocument payload, ReadOnlySpan<byte> contentBytes, ReadOnlySpan<byte> signatureSegment)
        {
            return SignatureValidationPolicy.TryValidateSignature(header, payload, contentBytes, signatureSegment);
        }

        private class DisabledJwtHeaderDocumentCache : IJwtHeaderDocumentCache
        {
            public bool Enabled => false;

            public void AddHeader(ReadOnlySpan<byte> rawHeader, JwtHeaderDocument header)
            {
            }

            public bool TryGetHeader(ReadOnlySpan<byte> buffer, [NotNullWhen(true)] out JwtHeaderDocument? header)
            {
                header = null;
                return false;
            }
        }
    }
}
