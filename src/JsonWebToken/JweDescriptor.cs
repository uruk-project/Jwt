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

        public JweDescriptor(JObject header, JwsDescriptor payload)
            : base(header, payload)
        {
        }

        public JweDescriptor(JwsDescriptor payload)
            : base(payload)
        {
        }

        public JweDescriptor(JObject payload)
            : base(new JwsDescriptor(payload))
        {
        }

        public JweDescriptor(JObject header, JObject payload)
            : base(header, new JwsDescriptor(payload))
        {
        }
    }
}
