﻿namespace JsonWebToken
{
    /// <summary>Represents the content types 'cty' of JWT. Used for nested JWT as defined at https://tools.ietf.org/html/rfc7519#section-5.2.</summary>
    public static class JwtContentTypeValues
    {
        /// <summary>https://tools.ietf.org/html/rfc7519#section-5.2</summary>
        public const string Jwt = "JWT";

        /// <summary>https://tools.ietf.org/html/rfc7517#section-7</summary>
        public const string Jwk = "jwk+json";

        /// <summary>https://tools.ietf.org/html/rfc7517#section-7</summary>
        public const string Jwks = "jwk-set+json";
    }
}
