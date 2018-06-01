namespace JsonWebToken.Validations
{
    public class IssuerValidation : RequiredClaimValidation<string>
    {
        public IssuerValidation(string issuer)
            :base(ClaimNames.Iss, issuer)
        {
        }

        //public TokenValidationResult TryValidate(ReadOnlySpan<char> token, JsonWebToken jwt)
        //{
        //    var issuer = jwt.Issuer;
        //    if (string.IsNullOrWhiteSpace(issuer))
        //    {

        //        return TokenValidationResult.MissingClaim(jwt, ClaimNames.Iss);
        //    }

        //    if (string.Equals(_issuer, issuer, StringComparison.Ordinal))
        //    {
        //        return TokenValidationResult.Success(jwt);
        //    }

        //    return TokenValidationResult.InvalidClaim(jwt, ClaimNames.Iss);
        //}
    }
}
