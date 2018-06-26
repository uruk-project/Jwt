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
        /// The number of segment in a JWE token.
        /// </summary>
        internal const int JweSegmentCount = 5;

        /// <summary>
        /// The number of segment in a JWS token.
        /// </summary>
        internal const int JwsSegmentCount = 3;

        /// <summary>
        /// The maximum number of segment in a JWT.
        /// </summary>
        internal const int MaxJwtSegmentCount = JweSegmentCount;

        internal const int MaxStackallocBytes = 1024 * 1024;

        internal static readonly int DecompressionBufferLength = 1024;
    }
}
