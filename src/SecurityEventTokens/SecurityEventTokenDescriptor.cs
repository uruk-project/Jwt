using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;

namespace JsonWebToken
{
    public class SecurityEventTokenDescriptor : JwsDescriptor
    {
        public const string SecurityEventTokenType = "secevent+jwt";

        private static readonly Dictionary<string, JTokenType[]> SetRequiredClaims = new Dictionary<string, JTokenType[]>
        {
            { Claims.Iss, new[] { JTokenType.String } },
            { Claims.Iat, new[] { JTokenType.Integer} },
            { Claims.Jti, new[] { JTokenType.String } },
            { Claims.Events, new[] { JTokenType.Object } }
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
        public JObject Events => GetClaim(Claims.Events);

        public void AddEvent(string eventName, JObject @event)
        {
            AddClaim(Claims.Events, new JProperty(eventName, @event));
        }

        public void AddEvent(string eventName, IEvent @event)
        {
            AddClaim(Claims.Events, new JProperty(eventName, JObject.FromObject(@event)));
        }

        /// <summary>
        /// Gets or sets the unique transaction identifier.
        /// </summary>
        public string TransactionNumber
        {
            get => GetStringClaim(Claims.Txn);
            set => AddClaim(Claims.Txn, value);
        }

        /// <summary>
        /// Gets or sets the date and time at which the event occurred.
        /// </summary>
        public DateTime? TimeOfEvent
        {
            get => GetDateTime(Claims.Toe);
            set => AddClaim(Claims.Toe, value);
        }

        protected override IReadOnlyDictionary<string, JTokenType[]> RequiredClaims => SetRequiredClaims;
    }
}
