using Newtonsoft.Json.Linq;

namespace JsonWebTokens
{
    public class JweDescriptor : JweDescriptor<JwsDescriptor>
    {
        public JweDescriptor()
        {
            Payload = new JwsDescriptor();
        }

        public JweDescriptor(JObject payload) 
        {
            Payload = new JwsDescriptor(payload);
        }

        public JweDescriptor(JwsDescriptor payload) : 
            base(payload)
        {          
        }
    }
}
