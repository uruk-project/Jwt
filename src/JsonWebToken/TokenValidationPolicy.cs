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
        public const int DefaultMaximumTokenSizeInBytes = 1024 * 1024 * 2;

        /// <summary>
        /// Represents an policy without any validation.
        /// </summary>
        public static readonly TokenValidationPolicy NoValidation = new TokenValidationPolicyBuilder()
                                                            .IgnoreSignature()
                                                            .IgnoreCriticalHeader()     
                                                            .Build();

        private readonly IList<IValidator> _validators;
        private readonly IDictionary<string, ICriticalHeaderHandler> _criticalHandlers;
        private readonly bool _ignoreCriticalHeader;

        internal TokenValidationPolicy(IList<IValidator> validators, IDictionary<string, ICriticalHeaderHandler> criticalHandlers, int maximumTokenSizeInBytes, bool ignoreCriticalHeader) 
        {
            _validators = validators ?? throw new ArgumentNullException(nameof(validators));
            _criticalHandlers = criticalHandlers ?? throw new ArgumentNullException(nameof(criticalHandlers));
            _ignoreCriticalHeader = ignoreCriticalHeader;
            MaximumTokenSizeInBytes = maximumTokenSizeInBytes;
        }

        public int MaximumTokenSizeInBytes { get; set; } = DefaultMaximumTokenSizeInBytes;

        public TokenValidationResult TryValidate(in TokenValidationContext context)
        {
            for (int i = 0; i < _validators.Count; i++)
            {
                var result = _validators[i].TryValidate(context);
                if (!result.Succedeed)
                {
                    return result;
                }
            }

            return TokenValidationResult.Success(context.Jwt);
        }

        public TokenValidationResult TryValidate(CriticalHeaderValidationContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (_ignoreCriticalHeader)
            {
                return TokenValidationResult.Success();
            }

            var header = context.Header;
            var crit = header.Crit;
            if (crit == null || crit.Count == 0)
            {
                return TokenValidationResult.Success();
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
                    if (_criticalHandlers.TryGetValue(criticalHeader, out ICriticalHeaderHandler handler))
                    {
                        if (!handler.TryHandle(context, criticalHeader))
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

            return TokenValidationResult.Success();
        }
    }
}
