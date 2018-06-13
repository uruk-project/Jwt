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

    /// <summary>
    /// https://tools.ietf.org/html/rfc7591#section-2.3
    /// </summary>
    public class SoftwareStatementDescriptor : JwsDescriptor
    {
        private static IReadOnlyDictionary<string, JTokenType[]> SoftwareStatementRequiredClaims = new Dictionary<string, JTokenType[]>
        {
            { ClaimNames.Iss, new [] { JTokenType.String } }
        };

        public SoftwareStatementDescriptor(JObject payload)
            : base(payload)
        {
        }

        /// <summary>
        /// Gets or sets the value of the 'software_id' claim.
        /// </summary>
        public string SoftwareId
        {
            get { return GetStringClaim(ClaimNames.SoftwareId); }
            set { AddClaim(ClaimNames.SoftwareId, value); }
        }
    }
}
