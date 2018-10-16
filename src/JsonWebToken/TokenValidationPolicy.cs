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

        private readonly IList<IValidation> _validations;

        public TokenValidationPolicy(IList<IValidation> validations)
        {
            _validations = validations ?? throw new ArgumentNullException(nameof(validations));
        }

        public int MaximumTokenSizeInBytes { get; set; } = DefaultMaximumTokenSizeInBytes;

        public TokenValidationResult TryValidate(in TokenValidationContext context)
        {
            for (int i = 0; i < _validations.Count; i++)
            {
                var result = _validations[i].TryValidate(context);
                if (!result.Succedeed)
                {
                    return result;
                }
            }

            return TokenValidationResult.Success(context.Jwt);
        }
    }
}
