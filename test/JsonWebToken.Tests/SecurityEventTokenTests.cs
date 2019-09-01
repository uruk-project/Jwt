﻿using JsonWebToken.Internal;
using Newtonsoft.Json;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using Xunit;
using System.Text;
#if NETCOREAPP3_0
using System.Text.Json;
#endif

namespace JsonWebToken.Tests
{
    public class SecurityEventTokenTests : IClassFixture<KeyFixture>
    {
        private readonly KeyFixture _keys;

        public SecurityEventTokenTests(KeyFixture keys)
        {
            _keys = keys;
        }

        [Fact]
        public void Write()
        {
            var descriptor = new SecurityEventTokenDescriptor();
            descriptor.Type = "secevent+jwt";
            descriptor.Algorithm = SignatureAlgorithm.None;
            descriptor.Issuer = "https://scim.example.com";
            descriptor.IssuedAt = EpochTime.ToDateTime(1458496404);
            descriptor.JwtId = "4d3559ec67504aaba65d40b0363faad8";
            descriptor.Audiences = new List<string> { "https://scim.example.com/Feeds/98d52461fa5bbc879593b7754", "https://scim.example.com/Feeds/5d7604516b1d08641d7676ee7" };

            var @event = new ScimCreateEvent
            {
                Ref = "https://scim.example.com/Users/44f6142df96bd6ab61e7521d9",
                Attributes = { "id", "name", "userName", "password", "emails" }
            };
            descriptor.AddEvent("urn:ietf:params:scim:event:create", @event);

            var writer = new JwtWriter();
            var jwt = writer.WriteTokenString(descriptor);

#if NETCOREAPP
            Assert.Equal("eyJ0eXAiOiJzZWNldmVudCtqd3QiLCJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwczovL3NjaW0uZXhhbXBsZS5jb20iLCJpYXQiOjE0NTg0OTY0MDQsImp0aSI6IjRkMzU1OWVjNjc1MDRhYWJhNjVkNDBiMDM2M2ZhYWQ4IiwiYXVkIjpbImh0dHBzOi8vc2NpbS5leGFtcGxlLmNvbS9GZWVkcy85OGQ1MjQ2MWZhNWJiYzg3OTU5M2I3NzU0IiwiaHR0cHM6Ly9zY2ltLmV4YW1wbGUuY29tL0ZlZWRzLzVkNzYwNDUxNmIxZDA4NjQxZDc2NzZlZTciXSwiZXZlbnRzIjp7InVybjppZXRmOnBhcmFtczpzY2ltOmV2ZW50OmNyZWF0ZSI6eyJyZWYiOiJodHRwczovL3NjaW0uZXhhbXBsZS5jb20vVXNlcnMvNDRmNjE0MmRmOTZiZDZhYjYxZTc1MjFkOSIsImF0dHJpYnV0ZSI6WyJpZCIsIm5hbWUiLCJ1c2VyTmFtZSIsInBhc3N3b3JkIiwiZW1haWxzIl19fX0.", jwt);
#else
            Assert.Equal("eyJ0eXAiOiJzZWNldmVudFx1MDAyQmp3dCIsImFsZyI6Im5vbmUifQ.eyJpc3MiOiJodHRwczovL3NjaW0uZXhhbXBsZS5jb20iLCJpYXQiOjE0NTg0OTY0MDQsImp0aSI6IjRkMzU1OWVjNjc1MDRhYWJhNjVkNDBiMDM2M2ZhYWQ4IiwiYXVkIjpbImh0dHBzOi8vc2NpbS5leGFtcGxlLmNvbS9GZWVkcy85OGQ1MjQ2MWZhNWJiYzg3OTU5M2I3NzU0IiwiaHR0cHM6Ly9zY2ltLmV4YW1wbGUuY29tL0ZlZWRzLzVkNzYwNDUxNmIxZDA4NjQxZDc2NzZlZTciXSwiZXZlbnRzIjp7InVybjppZXRmOnBhcmFtczpzY2ltOmV2ZW50OmNyZWF0ZSI6eyJyZWYiOiJodHRwczovL3NjaW0uZXhhbXBsZS5jb20vVXNlcnMvNDRmNjE0MmRmOTZiZDZhYjYxZTc1MjFkOSIsImF0dHJpYnV0ZSI6WyJpZCIsIm5hbWUiLCJ1c2VyTmFtZSIsInBhc3N3b3JkIiwiZW1haWxzIl19fX0.", jwt);
#endif
        }

        [JsonObject]
        private class ScimCreateEvent
        {
            private List<string> _attributes = new List<string>();

            [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = "ref", Required = Required.Default)]
            public string Ref { get; set; }

            [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = "attributes", Required = Required.Default)]
            public IList<string> Attributes => _attributes;

            public static implicit operator JwtObject(ScimCreateEvent @event)
            {
                var jwtObject = new JwtObject();
                jwtObject.Add(new JwtProperty("ref", @event.Ref));
                jwtObject.Add(new JwtProperty("attribute", new JwtArray(@event._attributes)));

                return jwtObject;
            }
        }

        [Fact]
        public void Read()
        {
            var reader = new JwtReader(_keys.Jwks);

            var policy = new TokenValidationPolicyBuilder()
                                .AcceptUnsecureToken()
                                .RequireSecurityEventToken()
                                .Build();
            var result = reader.TryReadToken("eyJ0eXAiOiJzZWNldmVudCtqd3QiLCJhbGciOiJub25lIn0.eyJqdGkiOiI0ZDM1NTllYzY3NTA0YWFiYTY1ZDQwYjAzNjNmYWFkOCIsImlhdCI6MTQ1ODQ5NjQwNCwiaXNzIjoiaHR0cHM6Ly9zY2ltLmV4YW1wbGUuY29tIiwiYXVkIjpbImh0dHBzOi8vc2NpbS5leGFtcGxlLmNvbS9GZWVkcy85OGQ1MjQ2MWZhNWJiYzg3OTU5M2I3NzU0IiwiaHR0cHM6Ly9zY2ltLmV4YW1wbGUuY29tL0ZlZWRzLzVkNzYwNDUxNmIxZDA4NjQxZDc2NzZlZTciXSwiZXZlbnRzIjp7InVybjppZXRmOnBhcmFtczpzY2ltOmV2ZW50OmNyZWF0ZSI6eyJyZWYiOiJodHRwczovL3NjaW0uZXhhbXBsZS5jb20vVXNlcnMvNDRmNjE0MmRmOTZiZDZhYjYxZTc1MjFkOSIsImF0dHJpYnV0ZXMiOlsiaWQiLCJuYW1lIiwidXNlck5hbWUiLCJwYXNzd29yZCIsImVtYWlscyJdfX19.", policy);
            var token = result.Token.AsSecurityEventToken();
            var events = token.Events;

            Assert.True(events.ContainsKey("urn:ietf:params:scim:event:create"));
            Assert.True(events["urn:ietf:params:scim:event:create"].ContainsKey("ref"));
            Assert.Equal("https://scim.example.com/Users/44f6142df96bd6ab61e7521d9", (string)events["urn:ietf:params:scim:event:create"]["ref"].Value);
        }

        internal class FixedSizedBufferWriter : IBufferWriter<byte>
        {
            private readonly byte[] _buffer;
            private int _count;

            public FixedSizedBufferWriter(int capacity)
            {
                _buffer = new byte[capacity];
            }

            public void Clear()
            {
                _count = 0;
            }

            public Span<byte> Free => _buffer.AsSpan(_count);

            public byte[] Formatted => _buffer.AsSpan(0, _count).ToArray();

            public Memory<byte> GetMemory(int minimumLength = 0) => _buffer.AsMemory(_count);

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public Span<byte> GetSpan(int minimumLength = 0) => _buffer.AsSpan(_count);

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public void Advance(int bytes)
            {
                _count += bytes;
                if (_count > _buffer.Length)
                {
                    throw new InvalidOperationException("Cannot advance past the end of the buffer.");
                }
            }
        }
    }
}
