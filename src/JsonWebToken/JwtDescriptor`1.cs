using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Diagnostics;

namespace JsonWebToken
{
    [DebuggerDisplay("{DebuggerDisplay(),nq}")]
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

        private string DebuggerDisplay()
        {
            return Serialize(Header, Formatting.Indented) + "." + Serialize(Payload, Formatting.Indented);
        }
    }
}
