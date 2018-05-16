namespace JsonWebToken
{
    /// <summary>
    /// List of registered claims from different sources
    /// http://tools.ietf.org/html/rfc7519#section-4
    /// http://openid.net/specs/openid-connect-core-1_0.html#IDToken
    /// </summary>
    public struct JwtRegisteredClaimNames
    {
        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#IDToken
        /// </summary>
        public const string Acr = "acr";

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#IDToken
        /// </summary>
        public const string Amr = "amr";

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Aud = "aud";

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#IDToken
        /// </summary>
        public const string AuthTime = "auth_time";

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#IDToken
        /// </summary>
        public const string Azp = "azp";

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Birthdate = "birthdate";

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string CHash = "c_hash";

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
        /// </summary>
        public const string AtHash = "at_hash";

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Email = "email";

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Exp = "exp";

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Gender = "gender";

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string FamilyName = "family_name";

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string GivenName = "given_name";

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Iat = "iat";

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Iss = "iss";

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Jti = "jti";

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Nonce = "nonce";

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Nbf = "nbf";

        /// <summary>
        /// http://openid.net/specs/openid-connect-frontchannel-1_0.html#OPLogout
        /// </summary>
        public const string Sid = "sid";

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Sub = "sub";

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Typ = "typ";
    }
}
