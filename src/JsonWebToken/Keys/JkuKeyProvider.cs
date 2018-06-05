using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;

namespace JsonWebToken
{
    public class JkuKeyProvider : HttpKeyProvider
    {
        public JkuKeyProvider(HttpDocumentRetriever documentRetriever)
            : base(documentRetriever)
        {
        }

        public override IReadOnlyList<JsonWebKey> GetKeys(JObject header)
        {
            return GetKeys(header, header.Value<string>(HeaderParameterNames.Jku));
        }

        protected override JsonWebKeySet DeserializeKeySet(string value)
        {
            return JsonConvert.DeserializeObject<JsonWebKeySet>(value);
        }
    }
}
