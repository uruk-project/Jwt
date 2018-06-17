using System;
using System.Collections.Generic;

namespace JsonWebToken
{
    public abstract class JwtDescriptor<TPayload> : JwtDescriptor where TPayload : class
    {
        public JwtDescriptor(IDictionary<string, object> header, TPayload payload)
            : base(header)
        {
            Payload = payload ?? throw new ArgumentNullException(nameof(payload));
        }

        public TPayload Payload { get; set; }
    }
}
