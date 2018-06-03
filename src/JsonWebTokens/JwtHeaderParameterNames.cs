namespace JsonWebTokens
{
    /// <summary>
    /// List of header parameter names see: http://tools.ietf.org/html/rfc7519#section-5.
    /// </summary>
    public static class JwtHeaderParameterNames
    {
        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.1
        /// </summary>
        public const string Alg = "alg";

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.10
        /// also:https://tools.ietf.org/html/rfc7519#section-5.2
        /// </summary>
        public const string Cty = "cty";

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7516#section-4.1.2
        /// </summary>
        public const string Enc = "enc";

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7518#section-4.7.1.1
        /// </summary>
        public const string IV = "iv";

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.2
        /// </summary>
        public const string Jku = "jku";

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.3
        /// </summary>
        public const string Jwk = "jwk";

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.4
        /// </summary>
        public const string Kid = "kid";

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.9
        /// also:https://tools.ietf.org/html/rfc7519#section-5.1
        /// </summary>
        public const string Typ = "typ";

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.6
        /// </summary>
        public const string X5c = "x5c";

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#page-12
        /// </summary>
        public const string X5t = "x5t";

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.5
        /// </summary>
        public const string X5u = "x5u";

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7516#section-4.1.3
        /// </summary>
        public const string Zip = "zip";
    }
}
