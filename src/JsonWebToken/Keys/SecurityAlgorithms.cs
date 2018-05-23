namespace JsonWebToken
{
    /// <summary>
    /// Constants for Security Algorithm.
    /// </summary>
    public static class SecurityAlgorithms
    {
        // See: https://tools.ietf.org/html/rfc7518#section-4.1
        public const string Aes128KW = "A128KW";
        public const string Aes192KW = "A192KW";
        public const string Aes256KW = "A256KW";
        public const string RsaPkcs1 = "RSA1_5";
        public const string RsaOaep = "RSA-OAEP";
        public const string RsaOaep256 = "RSA-OAEP-256";
        public const string Direct = "dir";

        // See: https://tools.ietf.org/html/rfc7518#appendix-A
        public const string Sha256 = "SHA256";
        public const string Sha384 = "SHA384";
        public const string Sha512 = "SHA512";

        // See: http://tools.ietf.org/html/rfc7518#section-3
        public const string EcdsaSha256 = "ES256";
        public const string EcdsaSha384 = "ES384";
        public const string EcdsaSha512 = "ES512";
        public const string HmacSha256 = "HS256";
        public const string HmacSha384 = "HS384";
        public const string HmacSha512 = "HS512";
        public const string None = "none";
        public const string RsaSha256 = "RS256";
        public const string RsaSha384 = "RS384";
        public const string RsaSha512 = "RS512";
        public const string RsaSsaPssSha256 = "PS256";
        public const string RsaSsaPssSha384 = "PS384";
        public const string RsaSsaPssSha512 = "PS512";

        // See : https://tools.ietf.org/html/rfc7518#section-5.1
        public const string Aes128CbcHmacSha256 = "A128CBC-HS256";
        public const string Aes192CbcHmacSha384 = "A192CBC-HS384";
        public const string Aes256CbcHmacSha512 = "A256CBC-HS512";
    }
}
