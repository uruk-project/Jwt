namespace JsonWebToken
{
    public interface IAuthenticatedEncryptorFactory
    {
        AuthenticatedEncryptor Create(JsonWebKey key, EncryptionAlgorithm encryptionAlgorithm);
    }
}