using System;

namespace JsonWebToken
{
    /// <summary>
    /// Represents a <see cref="Signer"/> factory.
    /// </summary>
    public interface ISignerFactory : IDisposable
    {
        Signer Create(JsonWebKey key, SignatureAlgorithm algorithm, bool willCreateSignatures);
    }
}