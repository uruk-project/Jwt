// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using JsonWebToken.Internal;
using System;
using System.Text;

namespace JsonWebToken
{
    public class SecurityEventTokenDescriptor : JwsDescriptor
    {
        public const string SecurityEventTokenType = "secevent+jwt";

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
        public JwtObject? Events => GetClaim(SetClaims.EventsUtf8);

        public void AddEvent(string eventName, JwtObject @event)
        {
            AddEvent(Encoding.UTF8.GetBytes(eventName).AsSpan(), @event);
        }
        
        public void AddEvent(ReadOnlySpan<byte> utf8EventName, JwtObject @event)
        {
            AddClaim(SetClaims.EventsUtf8, new JwtProperty(utf8EventName, @event));
        }

        /// <summary>
        /// Gets or sets the unique transaction identifier.
        /// </summary>
        public string? TransactionNumber
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

        public override void Validate()
        {
            base.Validate();
            RequireClaim(Claims.IssUtf8, JwtTokenType.String);
            RequireClaim(Claims.IatUtf8, JwtTokenType.Integer);
            RequireClaim(Claims.JtiUtf8, JwtTokenType.String);
            RequireClaim(SetClaims.EventsUtf8, JwtTokenType.Object);
        }
    }
}
