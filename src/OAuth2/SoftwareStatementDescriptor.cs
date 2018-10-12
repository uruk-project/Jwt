using System.Collections.Generic;
using JsonWebToken.Internal;
using Newtonsoft.Json.Linq;

namespace JsonWebToken
{
    /// <summary>
    /// https://tools.ietf.org/html/rfc7591#section-2.3
    /// </summary>
    public class SoftwareStatementDescriptor : JwsDescriptor
    {
        private static readonly IReadOnlyDictionary<string, JTokenType[]> SoftwareStatementRequiredClaims = new Dictionary<string, JTokenType[]>
        {
            { Claims.Iss, new [] { JTokenType.String } }
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
            get { return GetStringClaim(Claims.SoftwareId); }
            set { AddClaim(Claims.SoftwareId, value); }
        }
    }
}
