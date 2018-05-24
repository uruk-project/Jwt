using Newtonsoft.Json;
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
        public JwksKeyProvider(string jwksAddress, HttpClientHandler handler)
            : base(new HttpDocumentRetriever(handler))
        {
            _jwksAddress = jwksAddress;
        }

        public JwksKeyProvider(string metadataAddress)
            : this(metadataAddress, new HttpDocumentRetriever())
        {
        }

        public override JsonWebKeySet GetKeys(JsonWebToken jwtToken)
        {
            return GetKeys(jwtToken, _jwksAddress);
        }

        protected override JsonWebKeySet DeserializeKeySet(string value)
        {
            return JsonConvert.DeserializeObject<JsonWebKeySet>(value);
        }
    }
}
