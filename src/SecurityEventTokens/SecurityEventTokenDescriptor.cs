using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;

namespace JsonWebToken
{
    public class SecurityEventTokenDescriptor : JwsDescriptor
    {
        private const string SecurityEventTokenType = "secevent+jwt";

        private static readonly Dictionary<string, JTokenType[]> SetRequiredClaims = new Dictionary<string, JTokenType[]>
        {
            { ClaimNames.Iss, new[] { JTokenType.String } },
            { ClaimNames.Iat, new[] { JTokenType.Integer} },
            { ClaimNames.Jti, new[] { JTokenType.String } },
            { ClaimNames.Events, new[] { JTokenType.Object } }
        };

        public SecurityEventTokenDescriptor()
        {
        }

        public SecurityEventTokenDescriptor(JObject payload)
            : base(payload)
        {
        }

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public IReadOnlyList<Event> Events
        {
            get { return GetListClaims(ClaimNames.Events)?.Select(e => Event.FromJson(e)).ToList(); }
            set { AddClaim(ClaimNames.Events, JObject.FromObject(value)); }
        }

        public void AddEvent(string eventName, Event @event)
        {
            AddClaim(ClaimNames.Events, new JProperty(eventName, JObject.FromObject(@event)));
        }

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string TransactionNumber
        {
            get { return GetStringClaim(ClaimNames.Tnx); }
            set { AddClaim(ClaimNames.Tnx, value); }
        }

        /// <summary>
        /// Authentication Context Class that the authentication performed satisfied.
        /// </summary>
        public DateTime? TimeOfEvent
        {
            get { return GetDateTime(ClaimNames.Toe); }
            set { AddClaim(ClaimNames.Toe, value); }
        }

        protected override IReadOnlyDictionary<string, JTokenType[]> RequiredClaims => SetRequiredClaims;
    }
}
