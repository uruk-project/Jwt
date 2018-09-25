using System;

namespace JsonWebToken
{
    public interface ISignerFactory : IDisposable
    {
        Signer Create(JsonWebKey key, SignatureAlgorithm algorithm, bool willCreateSignatures);
    }
}