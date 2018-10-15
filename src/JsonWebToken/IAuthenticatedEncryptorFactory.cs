using System;

namespace JsonWebToken
{
    public interface IAuthenticatedEncryptorFactory : IDisposable
    {
        AuthenticatedEncryptor Create(JsonWebKey key, EncryptionAlgorithm encryptionAlgorithm);
    }
}