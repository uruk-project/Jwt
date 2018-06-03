using Newtonsoft.Json.Linq;

namespace JsonWebTokens
{
    public interface IKeyProvider
    {
        JsonWebKeySet GetKeys(JObject header);
    }
}
