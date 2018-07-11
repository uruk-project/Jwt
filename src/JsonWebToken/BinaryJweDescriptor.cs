using Newtonsoft.Json.Linq;

namespace JsonWebToken
{
    public class BinaryJweDescriptor : EncryptedJwtDescriptor<byte[]>
    {
        public BinaryJweDescriptor(byte[] payload)
            : base(payload)
        {
        }

        public BinaryJweDescriptor(JObject header, byte[] payload)
            : base(header, payload)
        {
        }

        public override string Encode(EncodingContext context)
        {
            return EncryptToken(Payload);
        }
    }
}
