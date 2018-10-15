namespace JsonWebToken.Internal
{
    public static class SymmetricKeyHelper
    {
        public static JsonWebKey CreateSymmetricKey(EncryptionAlgorithm encryptionAlgorithm, JsonWebKey staticKey)
        {
            if (staticKey != null)
            {
                return staticKey;
            }

            return SymmetricJwk.GenerateKey(encryptionAlgorithm.RequiredKeySizeInBytes << 3);
        }
    }
}