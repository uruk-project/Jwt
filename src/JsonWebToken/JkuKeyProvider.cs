using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace JsonWebToken
{
    public class JkuKeyProvider : HttpKeyProvider
    {
        public JkuKeyProvider(HttpDocumentRetriever documentRetriever)
            : base(documentRetriever)
        {
        }

        public override JsonWebKeySet GetKeys(JsonWebToken jwtToken)
        {
            return GetKeys(jwtToken, jwtToken.Header[JwtHeaderParameterNames.Jku]?.Value<string>());
        }

        protected override JsonWebKeySet DeserializeKeySet(string value)
        {
            return JsonConvert.DeserializeObject<JsonWebKeySet>(value);
        }
    }
}
