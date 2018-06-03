using System;

namespace JsonWebTokens
{
    public interface IValidation
    {
        TokenValidationResult TryValidate(ReadOnlySpan<char> token, JsonWebToken jwt);
    }
}
