using System;

namespace JsonWebToken
{
    public interface IKeyWrapperFactory : IDisposable
    {
        KeyWrapper Create(JsonWebKey key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm contentEncryptionAlgorithm);
    }
}