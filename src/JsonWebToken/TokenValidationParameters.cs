using System;
using System.Collections.Generic;

namespace JsonWebToken
{
    public class TokenValidationParameters
    {
        public static TokenValidationParameters NoValidation = new TokenValidationBuilder()
                                                            .IgnoreSignature()
                                                            .Build();

        private readonly IList<IValidation> _validations;

        public TokenValidationParameters(IList<IValidation> validations)
        {
            _validations = validations ?? throw new ArgumentNullException(nameof(validations));
        }

        public int MaximumTokenSizeInBytes { get; set; }

        public TokenValidationResult TryValidate(TokenValidationContext context)
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
