using Xunit;

namespace JsonWebToken.Tests
{
    public class SecEventValidationTests : IClassFixture<KeyFixture>
    {
        private readonly KeyFixture _keys;

        public SecEventValidationTests(KeyFixture keys)
        {
            _keys = keys;
        }

        [Fact]
        public void Read()
        {
            var policy = new TokenValidationPolicyBuilder()
                                .AcceptUnsecureTokenByDefault()
                                .RequireSecEventToken()
                                .WithDecryptionKeys(_keys.Jwks)
                                .Build();
            var result = Jwt.TryParse("eyJ0eXAiOiJzZWNldmVudCtqd3QiLCJhbGciOiJub25lIn0.eyJqdGkiOiI0ZDM1NTllYzY3NTA0YWFiYTY1ZDQwYjAzNjNmYWFkOCIsImlhdCI6MTQ1ODQ5NjQwNCwiaXNzIjoiaHR0cHM6Ly9zY2ltLmV4YW1wbGUuY29tIiwiYXVkIjpbImh0dHBzOi8vc2NpbS5leGFtcGxlLmNvbS9GZWVkcy85OGQ1MjQ2MWZhNWJiYzg3OTU5M2I3NzU0IiwiaHR0cHM6Ly9zY2ltLmV4YW1wbGUuY29tL0ZlZWRzLzVkNzYwNDUxNmIxZDA4NjQxZDc2NzZlZTciXSwiZXZlbnRzIjp7InVybjppZXRmOnBhcmFtczpzY2ltOmV2ZW50OmNyZWF0ZSI6eyJyZWYiOiJodHRwczovL3NjaW0uZXhhbXBsZS5jb20vVXNlcnMvNDRmNjE0MmRmOTZiZDZhYjYxZTc1MjFkOSIsImF0dHJpYnV0ZXMiOlsiaWQiLCJuYW1lIiwidXNlck5hbWUiLCJwYXNzd29yZCIsImVtYWlscyJdfX19.", policy, out var jwt);
            Assert.True(result);

            jwt.Payload.TryGetClaim(SecEventClaimNames.Events.EncodedUtf8Bytes, out var events);
            Assert.Equal("https://scim.example.com/Users/44f6142df96bd6ab61e7521d9", events["urn:ietf:params:scim:event:create"]["ref"].GetString());
            Assert.True(events.ContainsKey("urn:ietf:params:scim:event:create"));
            Assert.True(events["urn:ietf:params:scim:event:create"].ContainsKey("ref"));
            Assert.False(events.ContainsKey("X"));
            Assert.False(events["urn:ietf:params:scim:event:create"].ContainsKey("Y"));
        }
    }
}
