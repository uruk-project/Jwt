// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken;
using JsonWebToken.Internal;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace JsonWebToken
{
    public class SecurityEventTokenDescriptor : JwsDescriptor
    {
        public const string SecurityEventTokenType = "secevent+jwt";

        private static readonly ReadOnlyDictionary<string, JTokenType[]> SetRequiredClaims = new ReadOnlyDictionary<string, JTokenType[]>(
            new Dictionary<string, JTokenType[]>          
        {           
            { Claims.Iss, new[] { JTokenType.String } },               
            { Claims.Iat, new[] { JTokenType.Integer} },               
            { Claims.Jti, new[] { JTokenType.String } },               
            { SetClaims.Events, new[] { JTokenType.Object } }             
        });

        public SecurityEventTokenDescriptor()
        {
        }

        public SecurityEventTokenDescriptor(JObject payload)
            : base(new Dictionary<string, object>(), payload)
        {
        }

        /// <summary>
        /// Gets or sets the set of event statements that each provide 
        /// information describing a single logical event that has occurred about a security subject.
        /// </summary>
        public JObject Events => GetClaim(SetClaims.Events);

        public void AddEvent(string eventName, JObject @event)
        {
            AddClaim(SetClaims.Events, new JProperty(eventName, @event));
        }

        public void AddEvent(string eventName, IEvent @event)
        {
            AddClaim(SetClaims.Events, new JProperty(eventName, JObject.FromObject(@event)));
        }

        /// <summary>
        /// Gets or sets the unique transaction identifier.
        /// </summary>
        public string TransactionNumber
        {
            get => GetStringClaim(SetClaims.Txn);
            set => AddClaim(SetClaims.Txn, value);
        }

        /// <summary>
        /// Gets or sets the date and time at which the event occurred.
        /// </summary>
        public DateTime? TimeOfEvent
        {
            get => GetDateTime(SetClaims.Toe);
            set => AddClaim(SetClaims.Toe, value);
        }

        protected override ReadOnlyDictionary<string, JTokenType[]> RequiredClaims => SetRequiredClaims;
    }
}
