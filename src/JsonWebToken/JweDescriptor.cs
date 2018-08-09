using Newtonsoft.Json.Linq;

namespace JsonWebToken
{
    public class JweDescriptor : JweDescriptor<JwsDescriptor>
    {
        public JweDescriptor()
            : base()
        {
            Header[HeaderParameters.Cty] = ContentTypeValues.Jwt;
        }

        public JweDescriptor(JObject header, JwsDescriptor payload)
            : base(header, payload)
        {
            Header[HeaderParameters.Cty] = ContentTypeValues.Jwt;
        }

        public JweDescriptor(JwsDescriptor payload)
            : base(payload)
        {
            Header[HeaderParameters.Cty] = ContentTypeValues.Jwt;
        }

        public JweDescriptor(JObject payload)
            : base(new JwsDescriptor(payload))
        {
            Header[HeaderParameters.Cty] = ContentTypeValues.Jwt;
        }

        public JweDescriptor(JObject header, JObject payload)
            : base(header, new JwsDescriptor(payload))
        {
            Header[HeaderParameters.Cty] = ContentTypeValues.Jwt;
        }
    }
}
