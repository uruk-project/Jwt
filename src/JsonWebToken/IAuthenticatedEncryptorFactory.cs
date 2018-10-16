using System;

namespace JsonWebToken
{
    /// <summary>
    /// Represents a factory used to creates <see cref="AuthenticatedEncryptor"/>.
    /// </summary>
    public interface IAuthenticatedEncryptorFactory : IDisposable
    {
        AuthenticatedEncryptor Create(JsonWebKey key, EncryptionAlgorithm encryptionAlgorithm);
    }
}