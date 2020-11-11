namespace JsonWebToken
{
    /// <summary>
    /// Represents the media types of JWT. Used for explicit typing. See https://tools.ietf.org/html/rfc8725#section-3.11
    /// </summary>
    public static class Oauth2MediaTypes
    {
        /// <summary>
        /// https://tools.ietf.org/html/rfc8417#section-2.3
        /// </summary>
        public const string SecurityEventToken = "secevent+jwt";
    }  
}
