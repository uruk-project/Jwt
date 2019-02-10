// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Text;

namespace JsonWebToken
{
    public class SecurityEventTokenDescriptor : JwsDescriptor
    {
        public const string SecurityEventTokenType = "secevent+jwt";

        private static readonly ReadOnlyDictionary<ReadOnlyMemory<byte>, JwtTokenType[]> SetRequiredClaims = new ReadOnlyDictionary<ReadOnlyMemory<byte>, JwtTokenType[]>(
            new Dictionary<ReadOnlyMemory<byte>, JwtTokenType[]>
        {
            { Claims.IssUtf8, new[] { JwtTokenType.String } },
            { Claims.IatUtf8, new[] { JwtTokenType.Integer} },
            { Claims.JtiUtf8, new[] { JwtTokenType.String } },
            { SetClaims.EventsUtf8, new[] { JwtTokenType.Object } }
        });

        public SecurityEventTokenDescriptor()
        {
        }

        public SecurityEventTokenDescriptor(JwtObject payload)
            : base(new JwtObject(), payload)
        {
        }

        /// <summary>
        /// Gets or sets the set of event statements that each provide 
        /// information describing a single logical event that has occurred about a security subject.
        /// </summary>
        public JwtObject Events => GetClaim(SetClaims.EventsUtf8.Span);

        public void AddEvent(string eventName, JwtObject @event)
        {
            AddEvent(Encoding.UTF8.GetBytes(eventName), @event);
        }

        public void AddEvent(ReadOnlyMemory<byte> utf8EventName, JwtObject @event)
        {
            AddClaim(SetClaims.EventsUtf8, new JwtProperty(utf8EventName, @event));
        }

        /// <summary>
        /// Gets or sets the unique transaction identifier.
        /// </summary>
        public string TransactionNumber
        {
            get => GetStringClaim(SetClaims.TxnUtf8);
            set => AddClaim(SetClaims.TxnUtf8, value);
        }

        /// <summary>
        /// Gets or sets the date and time at which the event occurred.
        /// </summary>
        public DateTime? TimeOfEvent
        {
            get => GetDateTime(SetClaims.ToeUtf8);
            set => AddClaim(SetClaims.ToeUtf8, value);
        }

        protected override ReadOnlyDictionary<ReadOnlyMemory<byte>, JwtTokenType[]> RequiredClaims => SetRequiredClaims;
    }
}
