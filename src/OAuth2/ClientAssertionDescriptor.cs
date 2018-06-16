using System.Collections.Generic;
using Newtonsoft.Json.Linq;

namespace JsonWebToken
{
    /// <summary>
    /// https://tools.ietf.org/html/rfc7523#section-2.2
    /// </summary>
    public class ClientAssertionDescriptor : JwsDescriptor
    {
        private static IReadOnlyDictionary<string, JTokenType[]> ClientAssertionRequiredClaims = new Dictionary<string, JTokenType[]>
        {
            { Claims.Iss, new [] { JTokenType.String } },
            { Claims.Sub, new [] { JTokenType.String } },
            { Claims.Aud, new [] { JTokenType.String, JTokenType.Array } },
            { Claims.Exp, new [] { JTokenType.Integer } }
        };

        public ClientAssertionDescriptor(JObject payload)
            : base(payload)
        {
        }

        public override void Validate()
        {
            if (Key == null)
            {
                throw new JwtDescriptorException("No key is defined.");
            }

            base.Validate();
        }

        protected override IReadOnlyDictionary<string, JTokenType[]> RequiredClaims => ClientAssertionRequiredClaims;
    }
}
