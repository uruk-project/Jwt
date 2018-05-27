using System;
using System.Collections.Generic;

namespace JsonWebToken
{
    public class TokenValidationParameters
    {
        public static TokenValidationParameters NoValidation = new TokenValidationBuilder()
                                                            .IgnoreSignature()
                                                            .Build();

        private readonly IList<IValidation> _rules;

        public TokenValidationParameters(IList<IValidation> rules)
        {
            _rules = rules;
        }

        public int MaximumTokenSizeInBytes { get; internal set; }

        public TokenValidationResult TryValidate(ReadOnlySpan<char> token, JsonWebToken jwt)
        {
            for (int i = 0; i < _rules.Count; i++)
            {
                var result = _rules[i].TryValidate(token, jwt);
                if (!result.Succedeed)
                {
                    return result;
                }
            }

            return TokenValidationResult.Success(jwt);
        }
    }
}
