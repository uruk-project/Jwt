namespace JsonWebToken
{
    // See: https://tools.ietf.org/html/rfc7518#section-4.1
    public static class KeyManagementAlgorithms
    {
        public const string Direct = "dir";

        public const string Aes128KW = "A128KW";
        public const string Aes192KW = "A192KW";
        public const string Aes256KW = "A256KW";

        public const string Aes128GcmKW = "A128GCMKW";
        public const string Aes192GcmKW = "A192GCMKW";
        public const string Aes256GcmKW = "A256GCMKW";

        public const string RsaPkcs1 = "RSA1_5";
        public const string RsaOaep = "RSA-OAEP";
        public const string RsaOaep256 = "RSA-OAEP-256";

        public const string EcdhEs = "ECDH-ES";

        public const string EcdhEsAes128KW = "ECDH-ES+A128KW";
        public const string EcdhEsAes192KW = "ECDH-ES+A192KW";
        public const string EcdhEsAes256KW = "ECDH-ES+A256KW";

        public const int DirectId = 1;
                     
        public const int Aes128KWId = 2;
        public const int Aes192KWId = 3;
        public const int Aes256KWId = 4;
                     
        public const int RsaPkcs1Id = 5;
        public const int RsaOaepId = 6;
        public const int RsaOaep256Id = 7;
                     
        public const int EcdhEsId = 8;
                     
        public const int EcdhEsAes128KWId = 9;
        public const int EcdhEsAes192KWId = 10;
        public const int EcdhEsAes256KWId = 11;
    }
}
