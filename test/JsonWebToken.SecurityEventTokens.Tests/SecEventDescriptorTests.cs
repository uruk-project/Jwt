using System.Collections.Generic;
using Newtonsoft.Json;
using Xunit;

namespace JsonWebToken.Tests
{
    public class SecEventDescriptorTests : IClassFixture<KeyFixture>
    {
        [Fact]
        public void Write_Success()
        {
            var descriptor = new SecEventDescriptor(Jwk.None, SignatureAlgorithm.None)
            {
                Payload = new JwtPayload
                {
                    { "iss", "https://scim.example.com" },
                    { "iat", 1458496404 },
                    { "jti", "4d3559ec67504aaba65d40b0363faad8" },
                    { "aud", new [] { "https://scim.example.com/Feeds/98d52461fa5bbc879593b7754", "https://scim.example.com/Feeds/5d7604516b1d08641d7676ee7" } },
                    { "events", new JsonObject
                        {
                            { "urn:ietf:params:scim:event:create", new ScimCreateEvent
                                {
                                    Ref = "https://scim.example.com/Users/44f6142df96bd6ab61e7521d9",
                                    Attributes = { "id", "name", "userName", "password", "emails" }
                                }
                            }
                        }
                    }
                }
            };

            var writer = new JwtWriter();
            var jwt = writer.WriteTokenString(descriptor);

#if !NETSTANDARD2_0
            Assert.Equal("eyJhbGciOiJub25lIiwidHlwIjoic2VjZXZlbnQrand0In0.eyJpc3MiOiJodHRwczovL3NjaW0uZXhhbXBsZS5jb20iLCJpYXQiOjE0NTg0OTY0MDQsImp0aSI6IjRkMzU1OWVjNjc1MDRhYWJhNjVkNDBiMDM2M2ZhYWQ4IiwiYXVkIjpbImh0dHBzOi8vc2NpbS5leGFtcGxlLmNvbS9GZWVkcy85OGQ1MjQ2MWZhNWJiYzg3OTU5M2I3NzU0IiwiaHR0cHM6Ly9zY2ltLmV4YW1wbGUuY29tL0ZlZWRzLzVkNzYwNDUxNmIxZDA4NjQxZDc2NzZlZTciXSwiZXZlbnRzIjp7InVybjppZXRmOnBhcmFtczpzY2ltOmV2ZW50OmNyZWF0ZSI6eyJyZWYiOiJodHRwczovL3NjaW0uZXhhbXBsZS5jb20vVXNlcnMvNDRmNjE0MmRmOTZiZDZhYjYxZTc1MjFkOSIsImF0dHJpYnV0ZXMiOlsiaWQiLCJuYW1lIiwidXNlck5hbWUiLCJwYXNzd29yZCIsImVtYWlscyJdfX19.", jwt);
#else
            Assert.Equal("eyJ0eXAiOiJzZWNldmVudFx1MDAyQmp3dCIsImFsZyI6Im5vbmUifQ.eyJpc3MiOiJodHRwczovL3NjaW0uZXhhbXBsZS5jb20iLCJpYXQiOjE0NTg0OTY0MDQsImp0aSI6IjRkMzU1OWVjNjc1MDRhYWJhNjVkNDBiMDM2M2ZhYWQ4IiwiYXVkIjpbImh0dHBzOi8vc2NpbS5leGFtcGxlLmNvbS9GZWVkcy85OGQ1MjQ2MWZhNWJiYzg3OTU5M2I3NzU0IiwiaHR0cHM6Ly9zY2ltLmV4YW1wbGUuY29tL0ZlZWRzLzVkNzYwNDUxNmIxZDA4NjQxZDc2NzZlZTciXSwiZXZlbnRzIjp7InVybjppZXRmOnBhcmFtczpzY2ltOmV2ZW50OmNyZWF0ZSI6eyJyZWYiOiJodHRwczovL3NjaW0uZXhhbXBsZS5jb20vVXNlcnMvNDRmNjE0MmRmOTZiZDZhYjYxZTc1MjFkOSIsImF0dHJpYnV0ZSI6WyJpZCIsIm5hbWUiLCJ1c2VyTmFtZSIsInBhc3N3b3JkIiwiZW1haWxzIl19fX0.", jwt);
#endif
        }

        [JsonObject]
        private class ScimCreateEvent
        {
            private readonly List<string> _attributes = new List<string>();

            [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = "ref", Required = Required.Default)]
            public string Ref { get; set; }

            [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = "attributes", Required = Required.Default)]
            public IList<string> Attributes => _attributes;
        }
    }
}
