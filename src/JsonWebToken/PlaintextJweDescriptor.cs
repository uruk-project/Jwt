using Newtonsoft.Json.Linq;

namespace JsonWebToken
{
    /// <summary>
    /// Defines an encrypted JWT with a <see cref="string"/> payload.
    /// </summary>
    public sealed class PlaintextJweDescriptor : EncryptedJwtDescriptor<string>
    {
        public PlaintextJweDescriptor(JObject header, string payload)
            : base(header, payload)
        {
        }

        public PlaintextJweDescriptor(string payload)
            : base(payload)
        {
        }

        public override string Encode(EncodingContext context)
        {
            return EncryptToken(context, Payload);
        }
    }
}
