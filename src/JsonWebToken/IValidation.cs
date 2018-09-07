using System;

namespace JsonWebToken
{
    public interface IValidation
    {
        TokenValidationResult TryValidate(in TokenValidationContext context);
    }
}
