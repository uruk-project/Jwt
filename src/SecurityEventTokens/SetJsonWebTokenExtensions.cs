using System;

namespace JsonWebTokens
{
    public static class SetJsonWebTokenExtensions
    {
        public static SecurityEventToken AsSecurityEventToken(this JsonWebToken token)
        {
            if (!token.Payload.HasClaim(ClaimNames.Events))
            {
                throw new InvalidOperationException();
            }

            return new SecurityEventToken(token);
        }
    }
}