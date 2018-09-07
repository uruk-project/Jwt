using Newtonsoft.Json.Linq;

namespace JsonWebToken
{
    public sealed class PlaintextJweDescriptor : EncryptedJwtDescriptor<string>
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
            return EncryptToken(context, Payload);
        }
    }
}
