using Newtonsoft.Json.Linq;

namespace JsonWebToken
{
    public interface IKeyProvider
    {
        JsonWebKeySet GetKeys(JObject header);
    }
}
