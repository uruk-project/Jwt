using Newtonsoft.Json.Linq;
using System.Collections.Generic;

namespace JsonWebToken
{
    public interface IKeyProvider
    {
        IReadOnlyList<JsonWebKey> GetKeys(JwtHeader header);
    }
}
