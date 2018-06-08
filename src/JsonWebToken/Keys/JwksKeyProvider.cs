using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using System.Net.Http;

namespace JsonWebToken
{
    public class JwksKeyProvider : HttpKeyProvider
    {
        private readonly string _jwksAddress;

        public JwksKeyProvider(string jwksAddress, HttpDocumentRetriever documentRetriever)
            : base(documentRetriever)
        {
            _jwksAddress = jwksAddress;
        }
        public JwksKeyProvider(string jwksAddress, HttpMessageHandler handler)
            : base(new HttpDocumentRetriever(handler))
        {
            _jwksAddress = jwksAddress;
        }

        public JwksKeyProvider(string metadataAddress)
            : this(metadataAddress, new HttpDocumentRetriever())
        {
        }

        public override IReadOnlyList<JsonWebKey> GetKeys(JwtHeader header)
        {
            return GetKeys(header, _jwksAddress);
        }

        protected override JsonWebKeySet DeserializeKeySet(string value)
        {
            return JsonConvert.DeserializeObject<JsonWebKeySet>(value);
        }
    }
}
