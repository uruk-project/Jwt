using Newtonsoft.Json.Linq;
using System.Collections.Generic;

namespace JsonWebToken
{
    public class PlaintextJweDescriptor : EncodedJwtDescriptor<string>
    {
        public PlaintextJweDescriptor(IDictionary<string, object> header, string payload)
            : base(header, payload)
        {
        }

        public PlaintextJweDescriptor(string payload)
            :this(new Dictionary<string, object>(), payload)
        {
        }

        public override string Encode()
        {
            return EncryptToken(Payload);
        }
    }
}
