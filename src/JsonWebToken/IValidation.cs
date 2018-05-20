namespace JsonWebToken
{
    public interface IValidation
    {
        TokenValidationResult TryValidate(JsonWebToken jwt);
    }
}
