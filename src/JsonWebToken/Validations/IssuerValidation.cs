namespace JsonWebToken.Validations
{
    public class IssuerValidation : RequiredClaimValidation<string>
    {
        public IssuerValidation(string issuer)
            :base(ClaimNames.Iss, issuer)
        {
        }
    }
}
