using System;

namespace JsonWebToken
{
    /// <summary>
    /// Represents a <see cref="KeyWrapper"/> factory.
    /// </summary>
    public interface IKeyWrapperFactory : IDisposable
    {
        KeyWrapper Create(JsonWebKey key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm contentEncryptionAlgorithm);
    }
}