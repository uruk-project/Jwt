namespace JsonWebToken
{
    /// <summary>
    /// Constants for Security Algorithm.
    /// </summary>
    public static class SignatureAlgorithms
    {
        // See: http://tools.ietf.org/html/rfc7518#section-3
        public const string HmacSha256 = "HS256";
        public const string HmacSha384 = "HS384";
        public const string HmacSha512 = "HS512";
        public const string RsaSha256 = "RS256";
        public const string RsaSha384 = "RS384";
        public const string RsaSha512 = "RS512";
        public const string EcdsaSha256 = "ES256";
        public const string EcdsaSha384 = "ES384";
        public const string EcdsaSha512 = "ES512";
        public const string RsaSsaPssSha256 = "PS256";
        public const string RsaSsaPssSha384 = "PS384";
        public const string RsaSsaPssSha512 = "PS512";
        public const string None = "none";

        // See: https://tools.ietf.org/html/rfc7518#appendix-A
        public const string Sha256 = "SHA256";
        public const string Sha384 = "SHA384";
        public const string Sha512 = "SHA512";

        public const int HmacSha256Id = 1;
        public const int HmacSha384Id = 2;
        public const int HmacSha512Id = 3;
        public const int RsaSha256Id = 4;
        public const int RsaSha384Id = 5;
        public const int RsaSha512Id = 6;
        public const int EcdsaSha256Id = 7;
        public const int EcdsaSha384Id = 8;
        public const int EcdsaSha512Id = 9;
        public const int RsaSsaPssSha256Id = 10;
        public const int RsaSsaPssSha384Id = 11;
        public const int RsaSsaPssSha512Id = 12;
        public const int NoneId = -1;

    }
}
