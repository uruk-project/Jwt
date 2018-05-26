using Newtonsoft.Json.Linq;

namespace JsonWebToken
{
    public class JweDescriptor : JweDescriptor<JwsDescriptor>
    {
        public JweDescriptor()
        {
            Payload = new JwsDescriptor();
        }

        public JweDescriptor(JwsDescriptor payload)
        {
            Payload = payload;
        }

        public JweDescriptor(JObject payload)
        {
            Payload = new JwsDescriptor((JObject)payload.DeepClone());
        }

        public override string Encode()
        {
            var payload = Payload.Encode();
            var rawData = EncryptToken(payload);

            return rawData;
        }
    }
}
