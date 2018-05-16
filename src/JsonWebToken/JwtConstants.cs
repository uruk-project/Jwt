namespace JsonWebToken
{
    /// <summary>
    /// Constants for Json Web tokens.
    /// </summary>
    public static class JwtConstants
    {
        /// <summary>
        /// Short header type.
        /// </summary>
        public const string HeaderType = "JWT";
        
        /// <summary>
        /// Short token type.
        /// </summary>
        public const string TokenType = "JWT";

        /// <summary>
        /// Long token type.
        /// </summary>
        public const string TokenTypeAlt = "urn:ietf:params:oauth:token-type:jwt";
     
        public const string JwsCompactSerializationCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-";

        /// <summary>
        /// The number of parts in a JWE token.
        /// </summary>
        internal const int JweSegmentCount = 5;

        /// <summary>
        /// The number of parts in a JWS token.
        /// </summary>
        internal const int JwsSegmentCount = 3;

        /// <summary>
        /// The maximum number of parts in a JWT.
        /// </summary>
        internal const int MaxJwtSegmentCount = 5;
    }
}
