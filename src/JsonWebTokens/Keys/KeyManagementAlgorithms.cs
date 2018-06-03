namespace JsonWebTokens
{
    // See: https://tools.ietf.org/html/rfc7518#section-4.1
    public static class KeyManagementAlgorithms
    {
        public const string Aes128KW = "A128KW";
        public const string Aes192KW = "A192KW";
        public const string Aes256KW = "A256KW";
        public const string RsaPkcs1 = "RSA1_5";
        public const string RsaOaep = "RSA-OAEP";
        public const string RsaOaep256 = "RSA-OAEP-256";
        public const string Direct = "dir";
    }
}
