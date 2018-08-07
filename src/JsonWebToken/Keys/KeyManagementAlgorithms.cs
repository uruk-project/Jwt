namespace JsonWebToken
{
    // See: https://tools.ietf.org/html/rfc7518#section-4.1
    public static class KeyManagementAlgorithms
    {
        public const string Direct = "dir";

        public const string Aes128KW = "A128KW";
        public const string Aes192KW = "A192KW";
        public const string Aes256KW = "A256KW";

        public const string RsaPkcs1 = "RSA1_5";
        public const string RsaOaep = "RSA-OAEP";
        public const string RsaOaep256 = "RSA-OAEP-256";

        public const string EcdhEs = "ECDH-ES";

        public const string EcdhEsAes128KW = "ECDH-ES+A128KW";
        public const string EcdhEsAes192KW = "ECDH-ES+A192KW";
        public const string EcdhEsAes256KW = "ECDH-ES+A256KW";
    }
}
