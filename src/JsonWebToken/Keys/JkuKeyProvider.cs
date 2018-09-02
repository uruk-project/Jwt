using Newtonsoft.Json;
using System.Collections.Generic;

namespace JsonWebToken
{
    public class JkuKeyProvider : HttpKeyProvider
    {
        public JkuKeyProvider(HttpDocumentRetriever documentRetriever)
            : base(documentRetriever)
        {
        }

        public override IReadOnlyList<JsonWebKey> GetKeys(JwtHeader header)
        {
            return GetKeys(header, header.Jku);
        }

        protected override JsonWebKeySet DeserializeKeySet(string value)
        {
            return JsonConvert.DeserializeObject<JsonWebKeySet>(value);
        }
    }
}
