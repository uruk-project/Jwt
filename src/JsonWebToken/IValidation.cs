namespace JsonWebToken
{
    /// <summary>
    /// Represents a validation to apply to a <see cref="TokenValidationContext"/>.
    /// </summary>
    public interface IValidation
    {
        TokenValidationResult TryValidate(in TokenValidationContext context);
    }
}
