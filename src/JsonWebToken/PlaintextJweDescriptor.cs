using Newtonsoft.Json.Linq;

namespace JsonWebToken
{
    public class PlaintextJweDescriptor : EncryptedJwtDescriptor<string>
    {
        public PlaintextJweDescriptor(JObject header, string payload)
            : base(header, payload)
        {
        }

        public PlaintextJweDescriptor(string payload)
            :base(payload)
        {
        }

        public override string Encode(EncodingContext context)
        {
            return EncryptToken(Payload);
        }
    }
}
