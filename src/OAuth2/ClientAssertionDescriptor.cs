using System.Collections.Generic;
using Newtonsoft.Json.Linq;

namespace JsonWebToken
{
    public class ClientAssertionDescriptor : JwsDescriptor
    {
        private static IReadOnlyDictionary<string, JTokenType[]> ClientAssertionRequiredClaims = new Dictionary<string, JTokenType[]>
        {
            { ClaimNames.Iss, new [] { JTokenType.String } },
            { ClaimNames.Sub, new [] { JTokenType.String } },
            { ClaimNames.Aud, new [] { JTokenType.String, JTokenType.Array } },
            { ClaimNames.Exp, new [] { JTokenType.Integer } }
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
