using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;

namespace JsonWebTokens
{
    public class SecurityEventTokenDescriptor : JwsDescriptor
    {
        public const string SecurityEventTokenType = "secevent+jwt";

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
        /// Gets or sets the set of event statements that each provide 
        /// information describing a single logical event that has occurred about a security subject.
        /// </summary>
        public JObject Events => GetClaim(ClaimNames.Events);

        public void AddEvent(string eventName, JObject @event)
        {
            AddClaim(ClaimNames.Events, new JProperty(eventName, @event));
        }

        public void AddEvent(string eventName, IEvent @event)
        {
            AddClaim(ClaimNames.Events, new JProperty(eventName, JObject.FromObject(@event)));
        }

        /// <summary>
        /// Gets or sets the unique transaction identifier.
        /// </summary>
        public string TransactionNumber
        {
            get => GetStringClaim(ClaimNames.Txn);
            set => AddClaim(ClaimNames.Txn, value);
        }

        /// <summary>
        /// Gets or sets the date and time at which the event occurred.
        /// </summary>
        public DateTime? TimeOfEvent
        {
            get => GetDateTime(ClaimNames.Toe);
            set => AddClaim(ClaimNames.Toe, value);
        }

        protected override IReadOnlyDictionary<string, JTokenType[]> RequiredClaims => SetRequiredClaims;
    }
}
