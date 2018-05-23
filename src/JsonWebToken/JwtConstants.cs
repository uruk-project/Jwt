namespace JsonWebToken
{
    /// <summary>
    /// Constants for Json Web tokens.
    /// </summary>
    public static class JwtConstants
    {
        /// <summary>
        /// JWT media type for 'typ' header parameter.
        /// </summary>
        public const string JwtMediaType = "JWT";

        /// <summary>
        /// JWT content type for 'cty' header parameter.
        /// </summary>
        public const string JwtContentType = "JWT";

        /// <summary>
        /// Long token type.
        /// </summary>
        public const string TokenTypeAlt = "urn:ietf:params:oauth:token-type:jwt";
     
        public const string JwsCompactSerializationCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-";

        /// <summary>
        /// The number of separators in a JWE token.
        /// </summary>
        internal const int JweSeparatorsCount = 4;

        /// <summary>
        /// The number of separators in a JWS token.
        /// </summary>
        internal const int JwsSeparatorsCount = 2;

        /// <summary>
        /// The maximum number of separators in a JWT.
        /// </summary>
        internal const int MaxJwtSeparatorsCount = 4;
    }
}
