using Newtonsoft.Json;
using System.Collections.Generic;
using Xunit;

namespace JsonWebToken.Tests
{
    public class SecurityEventTokenTests
    {
        [Fact(Skip = "RFC draft is invalid.")]
        public void Create()
        {
            var descriptor = new SecurityEventTokenDescriptor();
            descriptor.Type = "secevent+jwt";
            descriptor.Algorithm = SignatureAlgorithms.None;
            descriptor.Issuer = "https://scim.example.com";
            descriptor.IssuedAt = EpochTime.ToDateTime(1458496404);
            descriptor.JwtId = "4d3559ec67504aaba65d40b0363faad8";
            descriptor.Audiences = new[] { "https://scim.example.com/Feeds/98d52461fa5bbc879593b7754", "https://scim.example.com/Feeds/5d7604516b1d08641d7676ee7" };

            var @event = new ScimCreateEvent
            {
                Ref = "https://scim.example.com/Users/44f6142df96bd6ab61e7521d9",
                Attributes = { "id", "name", "userName", "password", "emails" }
            };
            descriptor.AddEvent("urn:ietf:params:scim:event:create", @event);

            var writer = new JsonWebTokenWriter();
            var jwt = writer.WriteToken(descriptor);
            Assert.Equal("eyJ0eXAiOiJzZWNldmVudCtqd3QiLCJhbGciOiJub25lIn0.eyJqdGkiOiI0ZDM1NTllYzY3NTA0YWFiYTY1ZDQwYjAzNjNmYWFkOCIsImlhdCI6MTQ1ODQ5NjQwNCwiaXNzIjoiaHR0cHM6Ly9zY2ltLmV4YW1wbGUuY29tIiwiYXVkIjpbImh0dHBzOi8vc2NpbS5leGFtcGxlLmNvbS9GZWVkcy85OGQ1MjQ2MWZhNWJiYzg3OTU5M2I3NzU0IiwiaHR0cHM6Ly9zY2ltLmV4YW1wbGUuY29tL0ZlZWRzLzVkNzYwNDUxNmIxZDA4NjQxZDc2NzZlZTciXSwiZXZlbnRzIjp7InVybjppZXRmOnBhcmFtczpzY2ltOmV2ZW50OmNyZWF0ZSI6eyJyZWYiOiJodHRwczovL3NjaW0uZXhhbXBsZS5jb20vVXNlcnMvNDRmNjE0MmRmOTZiZDZhYjYxZTc1MjFkOSIsImF0dHJpYnV0ZXMiOlsiaWQiLCJuYW1lIiwidXNlck5hbWUiLCJwYXNzd29yZCIsImVtYWlscyJdfX19.", jwt);
        }

        [JsonObject]
        private class ScimCreateEvent : Event
        {
            [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = "ref", Required = Required.Default)]
            public string Ref { get; set; }

            [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = "attributes", Required = Required.Default)]
            public IList<string> Attributes { get; set; } = new List<string>();
        }
    }
}
