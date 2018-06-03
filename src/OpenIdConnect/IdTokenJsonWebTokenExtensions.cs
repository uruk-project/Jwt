namespace JsonWebToken
{
    public static class IdTokenJsonWebTokenExtensions
    {
        public static IdToken AsIdToken(this JsonWebToken token)
        {
            return new IdToken(token);
        }
    }
}