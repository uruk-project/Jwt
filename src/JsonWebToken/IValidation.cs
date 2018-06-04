using System;

namespace JsonWebToken
{
    public interface IValidation
    {
        TokenValidationResult TryValidate(TokenValidationContext context);
    }
}
