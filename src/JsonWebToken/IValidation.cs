using System;

namespace JsonWebToken
{
    public interface IValidation
    {
        TokenValidationResult TryValidate(ReadOnlySpan<char> token, JsonWebToken jwt);
    }
}
