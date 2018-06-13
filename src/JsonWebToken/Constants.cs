namespace JsonWebToken
{
    /// <summary>
    /// Constants for Json Web tokens.
    /// </summary>
    internal static class Constants
    {
        /// <summary>
        /// Base64Url symbol table;
        /// </summary>
        internal const string JwsCompactSerializationCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-";

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

        internal const int MaxStackallocBytes = 1024 * 1024;

        internal static readonly int DecompressionBufferLength = 1024;
    }
}
