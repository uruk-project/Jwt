namespace JsonWebToken
{
    public interface IKeyProvider
    {
        JsonWebKeySet GetKeys(JsonWebToken jwtToken);
    }
}
