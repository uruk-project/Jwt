using Newtonsoft.Json.Linq;

namespace JsonWebToken
{
    public class JsonWebTokenBuilder
    {
        private readonly JObject _payload = new JObject();

        public JweDescriptor Build()
        {
            return new JweDescriptor(_payload);
        }

        public JsonWebTokenBuilder Sign(JsonWebKey key)
        {
            return this;
        }

        public JsonWebTokenBuilder Sign(JsonWebKey key, string algoritmh)
        {
            return this;
        }

        public JsonWebTokenBuilder Encrypt(JsonWebKey key, string encryptionAlgorithm)
        {
            return this;
        }

        public JsonWebTokenBuilder Claim(string name, object value)
        {
            return this;
        }

        public JsonWebTokenBuilder Header(string name, object value)
        {
            return this;
        }
    }
}
