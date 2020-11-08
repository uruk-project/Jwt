// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Collections;
using System.Text;
using System.Text.Json;
using JsonWebToken.Internal;

namespace JsonWebToken
{
    public class SecurityEventTokenDescriptor : JwsDescriptor
    {
        public const string SecurityEventTokenType = "secevent+jwt";
        private JwtEvents _events = new JwtEvents();

        public SecurityEventTokenDescriptor()
        {
            Payload.Add("events", _events);
        }

        /// <summary>
        /// Gets or sets the set of event statements that each provide 
        /// information describing a single logical event that has occurred about a security subject.
        /// </summary>
        public JwtEvents Events
        {
            get
            {
                return _events;
            }

            set
            {
                _events = value;
                Payload.Add(SetClaims.Events, value);
            }
        }

        public void AddEvent(string eventName, object @event)
        {
            Events.Add(eventName, @event);
        }

        public override void Validate()
        {
            base.Validate();
            RequireClaim(Claims.Iss, JsonValueKind.String);
            RequireClaim(Claims.Iat, JsonValueKind.Number);
            RequireClaim(Claims.Jti, JsonValueKind.String);
            RequireClaim(SetClaims.Events, JsonValueKind.Object);
        }
    }

    /// <summary>
    /// Represents the events of a Security Event Token.
    /// </summary>
    public sealed class JwtEvents : IEnumerable, IJwtSerializable
    {
        private readonly MemberStore _events;

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtPayload"/> class.
        /// </summary>
        public JwtEvents()
        {
            _events = MemberStore.CreateForHeader();
        }

        internal MemberStore Inner => _events;

        internal void CopyTo(JwtEvents destination)
        {
            _events.CopyTo(destination._events);
        }

        /// <summary>
        /// Determines whether the <see cref="JwtPayload"/> contains the specified key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public bool ContainsKey(string key)
        {
            return _events.ContainsKey(key);
        }

        /// <summary>
        /// Gets the value associated with the specified key.
        /// </summary>
        public bool TryGetValue(string key, out JwtMemberX value)
        {
            return _events.TryGetValue(key, out value);
        }

        /// <inheritsdoc />
        public override string ToString()
        {
            using var bufferWriter = new PooledByteBufferWriter();
            using (var writer = new Utf8JsonWriter(bufferWriter, new JsonWriterOptions { Indented = true }))
            {
                _events.WriteTo(writer);
            }

            var input = bufferWriter.WrittenSpan;
            return Utf8.GetString(input);
        }

        internal void Add(JwtMemberX value)
        {
            _events.TryAdd(value);
        }

        /// <summary>
        /// Adds the claim of type <see cref="object"/> to the current <see cref="JwtPayload"/>.
        /// </summary>
        public void Add(string claimName, object value)
        {
            _events.TryAdd(new JwtMemberX(claimName, value));
        }

        /// <inheritdoc/>
        public IEnumerator GetEnumerator()
        {
            throw new NotImplementedException();
        }

        public void WriteTo(Utf8JsonWriter writer)
        {
            _events.WriteTo(writer);
        }
    }
}
