using Newtonsoft.Json.Linq;
using System;

namespace JsonWebToken
{
    public abstract class JwtDescriptor<TPayload> : JwtDescriptor where TPayload : class
    {
        public JwtDescriptor(JObject header, TPayload payload)
            : base(header)
        {
            Payload = payload ?? throw new ArgumentNullException(nameof(payload));
        }

        public JwtDescriptor(TPayload payload)
            : base()
        {
            Payload = payload ?? throw new ArgumentNullException(nameof(payload));
        }

        public TPayload Payload { get; set; }
    }
}
