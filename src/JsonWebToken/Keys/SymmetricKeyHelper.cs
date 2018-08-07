namespace JsonWebToken
{
    public static class SymmetricKeyHelper
    {
        public static JsonWebKey CreateSymmetricKey(string encryptionAlgorithm, JsonWebKey staticKey)
        {
            if (staticKey != null)
            {
                return staticKey;
            }

            switch (encryptionAlgorithm)
            {
                case ContentEncryptionAlgorithms.Aes128CbcHmacSha256:
                    return SymmetricJwk.GenerateKey(256);
                case ContentEncryptionAlgorithms.Aes192CbcHmacSha384:
                    return SymmetricJwk.GenerateKey(384);
                case ContentEncryptionAlgorithms.Aes256CbcHmacSha512:
                    return SymmetricJwk.GenerateKey(512);
                default:
                    throw new JsonWebTokenEncryptionFailedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSuportedAlgorithmForKeyWrap, encryptionAlgorithm));
            }
        }
    }
}