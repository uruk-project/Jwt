using System;

namespace JsonWebToken.Validations
{
    public class IssuerValidation : IValidation
    {
        private readonly string _issuer;

        public IssuerValidation(string issuer)
        {
            _issuer = issuer;
        }

        public TokenValidationResult TryValidate(ReadOnlySpan<char> token, JsonWebToken jwt)
        {
            var issuer = jwt.Issuer;
            if (string.IsNullOrWhiteSpace(issuer))
            {
                return TokenValidationResult.MissingIssuer(jwt);
            }

            if (string.Equals(_issuer, issuer, StringComparison.Ordinal))
            {
                return TokenValidationResult.Success(jwt);
            }

            return TokenValidationResult.InvalidIssuer(jwt);
        }
    }
}
