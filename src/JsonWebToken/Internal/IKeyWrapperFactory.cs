namespace JsonWebToken
{
    public interface IKeyWrapperFactory
    {
        KeyWrapper Create(JsonWebKey key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm contentEncryptionAlgorithm);
    }
}