namespace JsonWebToken
{
    public static class SymmetricKeyHelper
    {
        public static JsonWebKey CreateSymmetricKey(in EncryptionAlgorithm encryptionAlgorithm, JsonWebKey staticKey)
        {
            if (staticKey != null)
            {
                return staticKey;
            }

            return SymmetricJwk.GenerateKey(encryptionAlgorithm.RequiredKeySizeInBytes << 3);
        }
    }
}