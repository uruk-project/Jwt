// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;

namespace JsonWebToken
{
    /// <summary>
    /// Defines the validations to apply to a JWT.
    /// </summary>
    public sealed class TokenValidationPolicy
    {
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

        internal TokenValidationPolicy(IValidator[] validators, Dictionary<string, ICriticalHeaderHandler> criticalHandlers, int maximumTokenSizeInBytes, bool ignoreCriticalHeader, SignatureValidationPolicy? signatureValidation)
        {
            _validators = validators ?? throw new ArgumentNullException(nameof(validators));
            _criticalHandlers = criticalHandlers ?? throw new ArgumentNullException(nameof(criticalHandlers));
            SignatureValidationPolicy = signatureValidation ?? throw new ArgumentNullException(nameof(signatureValidation));
            _ignoreCriticalHeader = ignoreCriticalHeader;
            MaximumTokenSizeInBytes = maximumTokenSizeInBytes;
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
        /// Try to validate the token, according to the <paramref name="jwt"/>.
        /// </summary>
        /// <param name="jwt"></param>
        /// <returns></returns>
        public TokenValidationResult TryValidate(Jwt jwt)
        {
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
