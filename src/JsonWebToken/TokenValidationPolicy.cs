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
                                                            .Build();

        private readonly IList<IValidator> _validators;

        public TokenValidationPolicy(IList<IValidator> validators)
        {
            _validators = validators ?? throw new ArgumentNullException(nameof(validators));
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
    }
}
