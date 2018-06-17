using Newtonsoft.Json.Linq;
using System.Collections.Generic;

namespace JsonWebToken
{
    public class JweDescriptor : JweDescriptor<JwsDescriptor>
    {
        public JweDescriptor()
            : base()
        {
        }

        public JweDescriptor(IDictionary<string, object> header)
            : base(header)
        {
        }

        public JweDescriptor(JwsDescriptor payload)
            : base(payload)
        {
        }

        public JweDescriptor(IDictionary<string, object> header, JwsDescriptor payload)
            : base(header, payload)
        {
        }

        public JweDescriptor(JObject payload)
            : base(new JwsDescriptor(payload))
        {
        }

        public JweDescriptor(IDictionary<string, object> header, JObject payload)
            : base(header, new JwsDescriptor(payload))
        {
        }
    }
}
