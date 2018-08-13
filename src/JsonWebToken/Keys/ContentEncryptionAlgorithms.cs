namespace JsonWebToken
{
    // See : https://tools.ietf.org/html/rfc7518#section-5.1
    public static class ContentEncryptionAlgorithms
    {
        public const string Aes128CbcHmacSha256 = "A128CBC-HS256";
        public const string Aes192CbcHmacSha384 = "A192CBC-HS384";
        public const string Aes256CbcHmacSha512 = "A256CBC-HS512";

        public const string Aes128Gcm = "A128GCM";
        public const string Aes192Gcm = "A192GCM";
        public const string Aes256Gcm = "A256GCM";

        public const int Aes128CbcHmacSha256Id = 1;
        public const int Aes192CbcHmacSha384Id = 2;
        public const int Aes256CbcHmacSha512Id = 3;
                     
        public const int Aes128GcmId = 4;
        public const int Aes192GcmId = 5;
        public const int Aes256GcmId = 6;
    }
}
