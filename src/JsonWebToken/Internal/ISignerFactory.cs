namespace JsonWebToken
{
    public interface ISignerFactory
    {
        Signer Create(JsonWebKey key, SignatureAlgorithm algorithm, bool willCreateSignatures);
    }
}